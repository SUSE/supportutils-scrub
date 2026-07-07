# parallel.py — opt-in (--jobs) process-parallel scrubbing.
#
# Why processes and not threads: the scrub phase is CPU-bound regex and Python's
# `re` holds the GIL, so threads give no speedup. Why this particular shape: the
# scrubbers are a *chained* pipeline that allocates fake values lazily, so naive
# per-file parallelism would assign the same real value different fakes in
# different workers. The safe decomposition is:
#
#   1. Pre-pass builds the IPv4 maps. Subnet allocation needs global
#      coordination, so workers only *discover* candidate subnets/IPs
#      (IPScrubber.discover, read-only) and the parent replays the allocation
#      (IPScrubber.replay) in file order — same maps as a serial learn pass.
#   2. Frozen dict scrubbers (hostname/domain/username/serial/keyword) are pure
#      read-only and safe as-is.
#   3. The late lazy scrubbers (email/password/cloud_token/ldap) run in workers
#      with deterministic=True so each worker independently produces the same
#      fake for the same input. Merging the per-worker dicts is then a union.
#
# Files larger than _CHUNK_THRESHOLD are split at line boundaries and their
# chunks scrubbed by multiple workers, so one huge messages.txt no longer pins
# a single core. This is safe because by that point every mapping is either
# frozen or allocated deterministically.
#
# Workers get the frozen mappings through a mode-0600 pickle file loaded once
# per worker process (ProcessPoolExecutor has no initializer on Python 3.6),
# instead of pickling the multi-MB dict into every task.
#
# The default serial path (--jobs 1) is unchanged and does not use this module.

import os
import sys
import pickle
import shutil
import tempfile
from concurrent.futures import ProcessPoolExecutor

from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.ldap_dn_scrubber import LdapDnScrubber
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.processor import (
    FileProcessor, BINARY_SA_PATTERN, BINARY_OBJ_PATTERN,
    SAR_XZ_PATTERN, SAR_PLAIN_PATTERN, _SCRUB_INFO_HEADER,
    compressed_opener,
)
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger

_CHUNK_THRESHOLD = 32 * 1024 * 1024
_CHUNK_MIN = 8 * 1024 * 1024


def _build_chain(frozen, config, deterministic, include_ldap):
    """Build the full scrubber chain from a frozen mappings dict.

    Order MUST match the serial chain in modes/archive.py and modes/folder.py.
    """
    keyword = None
    if frozen.get('keyword'):
        keyword = KeywordScrubber(mappings={'keyword': frozen['keyword']})
        if not keyword.is_loaded():
            keyword = None

    serial = SerialScrubber(mappings=frozen)
    serial.serial_dict = dict(frozen.get('serial', {}))

    chain = [
        IPScrubber(config, mappings=frozen),
        IPv6Scrubber(config, mappings=frozen, deterministic=deterministic),
        MACScrubber(config, mappings=frozen, deterministic=deterministic),
        keyword,
        # Email must run before hostname/domain: once the domain part is
        # rewritten the address no longer matches EMAIL_RE and the local
        # part (often firstname.lastname) would survive.
        EmailScrubber(mappings=frozen, deterministic=deterministic),
        HostnameScrubber(dict(frozen.get('hostname', {}))),
        DomainScrubber(dict(frozen.get('domain', {}))),
    ]
    if include_ldap:
        chain.append(LdapDnScrubber(mappings=frozen, deterministic=deterministic))
    chain += [
        UsernameScrubber(dict(frozen.get('user', {}))),
        PasswordScrubber(mappings=frozen, deterministic=deterministic),
        CloudTokenScrubber(mappings=frozen, deterministic=deterministic),
        serial,
    ]
    return [s for s in chain if s is not None]


# --- IPv4 discovery pre-pass (workers) -------------------------------------

class _IPDiscoverCollector:
    """Duck-typed 'ip' scrubber for FileProcessor(learn_only=True): records
    IPScrubber.discover() output per file instead of allocating, so the sar/
    binary file handling and config gates stay identical to a real learn."""
    name = 'ip'
    skip_files = frozenset()

    def __init__(self, config):
        self._ip = IPScrubber(config, mappings={})
        self.current = None
        self.results = {}

    def learn(self, text):
        self.results[self.current] = self._ip.discover(text)

    def scrub(self, text):
        return text

    @property
    def mapping(self):
        return {}


def _discover_batch(payload):
    batch, config, verbose = payload
    logger = SupportutilsScrubLogger(log_level="verbose" if verbose else "normal")
    collector = _IPDiscoverCollector(config)
    fp = FileProcessor(config, [collector], learn_only=True)
    for path in batch:
        collector.current = path
        try:
            fp.process_file(path, logger, verbose, dry_run=True)
        except Exception as e:
            logger.error(f"discover pre-pass failed for {path}: {e}")
    return collector.results


def _discover_chunk(payload):
    """Discovery for one line-aligned byte range of a large file. discover()
    is stateless, so per-chunk results concatenated in order are equivalent
    to whole-file discovery (replay dedups repeats via its cache)."""
    path, start, end, config = payload
    ip = IPScrubber(config, mappings={})
    with open(path, 'rb') as f:
        f.seek(start)
        data = f.read(end - start)
    return ip.discover(data.decode('utf-8', errors='ignore'))


# --- worker-side context ----------------------------------------------------

# ctx_path -> (FileProcessor, base_keys, logger, verbose); each worker process
# builds its chain once from the pickle file and reuses it for every task.
_CTX = {}


def _get_ctx(ctx_path):
    ctx = _CTX.get(ctx_path)
    if ctx is None:
        with open(ctx_path, 'rb') as f:
            frozen, config, include_ldap, verbose = pickle.load(f)
        logger = SupportutilsScrubLogger(log_level="verbose" if verbose else "normal")
        scrubbers = _build_chain(frozen, config, deterministic=True,
                                 include_ldap=include_ldap)
        fp = FileProcessor(config, scrubbers)
        base_keys = {s.name: frozenset(s.mapping) for s in fp.scrubbers}
        ctx = (fp, base_keys, logger, verbose)
        _CTX[ctx_path] = ctx
    return ctx


def _map_diffs(fp, base_keys):
    """Mappings added in this worker since the chain was built from frozen."""
    diffs = {}
    for s in fp.scrubbers:
        base = base_keys[s.name]
        cur = s.mapping
        if len(cur) != len(base):
            diffs[s.name] = {k: v for k, v in cur.items() if k not in base}
    ipv6_s = fp['ipv6']
    extra = {'ipv6_subnet': dict(ipv6_s.subnet_map) if ipv6_s else {}}
    return diffs, extra


def _scrub_batch(payload):
    """Worker entrypoint: scrub a batch of files in place, return maps + hits."""
    ctx_path, batch = payload
    fp, base_keys, logger, verbose = _get_ctx(ctx_path)

    hits = {}
    # Per-file output from process_file is noisy when interleaved; silence it.
    devnull = open(os.devnull, 'w')
    saved_stdout = sys.stdout
    sys.stdout = devnull
    try:
        for path in batch:
            before = {s.name: len(s.mapping) for s in fp.scrubbers}
            fp.process_file(path, logger, verbose)
            grew = [name for name, prev in before.items() if len(fp[name].mapping) > prev]
            if grew:
                hits[os.path.basename(path)] = grew
    finally:
        sys.stdout = saved_stdout
        devnull.close()

    diffs, extra = _map_diffs(fp, base_keys)
    return diffs, hits, extra


def _scrub_chunk(payload):
    """Worker entrypoint: scrub one line-aligned byte range of a large file
    into a part file. The parent reassembles the parts in order."""
    ctx_path, path, idx, start, end = payload
    fp, base_keys, logger, verbose = _get_ctx(ctx_path)

    with open(path, 'rb') as f:
        f.seek(start)
        data = f.read(end - start)
    text = data.decode('utf-8', errors='ignore')

    before = {s.name: len(s.mapping) for s in fp.scrubbers}
    scrubbed = fp._scrub_content(text, os.path.basename(path), logger)
    grew = [name for name, prev in before.items() if len(fp[name].mapping) > prev]

    part_path = f"{path}.scrubpart{idx:05d}"
    with open(part_path, 'w', encoding='utf-8') as pf:
        pf.write(scrubbed)

    diffs, extra = _map_diffs(fp, base_keys)
    return path, idx, part_path, scrubbed != text, diffs, extra, grew


def _chunk_bounds(path, jobs):
    """Split a file into line-aligned (start, end) byte ranges. Splitting only
    at newlines keeps every scrubber's view intact — all patterns match within
    a single line. Safe for UTF-8: no multi-byte sequence contains 0x0A."""
    size = os.path.getsize(path)
    target = max(_CHUNK_MIN, size // (jobs * 2) + 1)
    bounds = []
    with open(path, 'rb') as f:
        pos = 0
        while pos < size:
            end = min(pos + target, size)
            if end < size:
                f.seek(end)
                f.readline()
                end = f.tell()
            bounds.append((pos, end))
            pos = end
    return bounds


def _is_chunkable(path):
    base = os.path.basename(path)
    if (BINARY_SA_PATTERN.match(base) or BINARY_OBJ_PATTERN.match(base)
            or SAR_XZ_PATTERN.match(base) or SAR_PLAIN_PATTERN.match(base)
            or compressed_opener(base)):
        return False  # special-cased in process_file; leave whole
    try:
        return os.path.getsize(path) > _CHUNK_THRESHOLD
    except OSError:
        return False


def _assemble_chunks(path, parts, changed):
    """Join scrubbed part files back into path (header only when changed),
    mirroring process_file's write-only-if-changed behavior."""
    try:
        if changed:
            tmp = path + '.scrubtmp'
            with open(tmp, 'w', encoding='utf-8') as out:
                out.write(_SCRUB_INFO_HEADER)
                for _, part_path in sorted(parts):
                    with open(part_path, 'r', encoding='utf-8') as pf:
                        shutil.copyfileobj(pf, out)
            os.replace(tmp, path)
    finally:
        for _, part_path in parts:
            try:
                os.remove(part_path)
            except OSError:
                pass


def _balanced_batches(files, n):
    """Split files into n buckets balanced by size (largest-first round-robin)."""
    def _size(p):
        try:
            return os.path.getsize(p)
        except OSError:
            return 0
    buckets = [[] for _ in range(n)]
    loads = [0] * n
    for path in sorted(files, key=_size, reverse=True):
        i = loads.index(min(loads))
        buckets[i].append(path)
        loads[i] += _size(path)
    return [b for b in buckets if b]


def scrub_in_parallel(report_files, frozen_seed, config, jobs, logger,
                      verbose=False, include_ldap=True):
    """Scrub report_files across `jobs` processes.

    frozen_seed: a mappings dict pre-populated with the globally-coordinated
        maps (hostname/domain/user/serial/keyword and any --mappings seed for
        ip/ipv6/mac/email/...). This function adds the ip/ipv6/mac maps via a
        discover/replay pre-pass, then fans the full chain out to workers.

    Returns (merged_mappings, file_hits).
    """
    jobs = max(1, jobs)

    with ProcessPoolExecutor(max_workers=jobs) as ex:
        # --- Pre-pass: build the IPv4 maps (no writes) ----------------------
        # IPv4 fake pools are small so subnet allocation needs global
        # coordination: workers discover in parallel, the parent replays the
        # allocation in file order — identical maps to a serial learn pass.
        # IPv6 and MAC allocate deterministically in workers (see
        # _build_chain), so they need no pre-pass.
        ip = IPScrubber(config, mappings=frozen_seed)
        disc_big = [p for p in report_files if _is_chunkable(p)]
        disc_big_set = set(disc_big)
        disc_small = [p for p in report_files if p not in disc_big_set]

        disc_chunk_futs = {}  # path -> [future per chunk, in order]
        for path in disc_big:
            disc_chunk_futs[path] = [
                ex.submit(_discover_chunk, (path, start, end, config))
                for start, end in _chunk_bounds(path, jobs)]
        discovered = {}
        for results in ex.map(_discover_batch,
                              [(b, config, verbose)
                               for b in _balanced_batches(disc_small, jobs)]):
            discovered.update(results)
        for path, futs in disc_chunk_futs.items():
            cidrs, tokens = [], []
            try:
                for fut in futs:
                    c, t = fut.result()
                    cidrs.extend(c)
                    tokens.extend(t)
                discovered[path] = (cidrs, tokens)
            except Exception as e:
                logger.error(f"discover pre-pass failed for {path}: {e}")

        for path in report_files:
            if path in discovered:
                try:
                    ip.replay(*discovered[path])
                except Exception as e:
                    logger.error(f"pre-pass replay failed for {path}: {e}")

        frozen = dict(frozen_seed)
        frozen['ip'] = dict(ip.mapping)
        frozen['subnet'] = dict(ip.subnet_dict)
        frozen['state'] = dict(ip.state)
        frozen.setdefault('ipv6', dict(frozen_seed.get('ipv6', {})))
        frozen.setdefault('ipv6_subnet', dict(frozen_seed.get('ipv6_subnet', {})))
        frozen.setdefault('mac', dict(frozen_seed.get('mac', {})))

        # --- Parallel apply --------------------------------------------------
        big_files = [p for p in report_files if _is_chunkable(p)]
        big_set = set(big_files)
        small_files = [p for p in report_files if p not in big_set]

        fd, ctx_path = tempfile.mkstemp(prefix='supportutils-scrub-ctx-', suffix='.pkl')
        merged = {k: dict(v) for k, v in frozen.items() if isinstance(v, dict)}
        file_hits = {}
        try:
            # mkstemp = mode 0600; the file holds real->fake mappings.
            with os.fdopen(fd, 'wb') as f:
                pickle.dump((frozen, config, include_ldap, verbose), f,
                            protocol=pickle.HIGHEST_PROTOCOL)

            futures = []
            for batch in _balanced_batches(small_files, jobs):
                futures.append(ex.submit(_scrub_batch, (ctx_path, batch)))

            chunk_parts = {}    # path -> [(idx, part_path)]
            chunk_changed = {}  # path -> bool
            chunk_failed = set()
            chunk_futures = []
            for path in big_files:
                for idx, (start, end) in enumerate(_chunk_bounds(path, jobs)):
                    chunk_futures.append(
                        (path, ex.submit(_scrub_chunk, (ctx_path, path, idx, start, end))))

            for fut in futures:
                diffs, hits, extra = fut.result()
                for name, d in diffs.items():
                    merged.setdefault(name, {}).update(d)
                merged.setdefault('ipv6_subnet', {}).update(extra.get('ipv6_subnet', {}))
                file_hits.update(hits)

            for fut_path, fut in chunk_futures:
                try:
                    path, idx, part_path, changed, diffs, extra, grew = fut.result()
                except Exception as e:
                    # Same failure mode as the serial path: the file is left
                    # unscrubbed. Log loudly and skip its assembly.
                    logger.error(f"chunk scrub failed for {fut_path}: {e}")
                    chunk_failed.add(fut_path)
                    continue
                chunk_parts.setdefault(path, []).append((idx, part_path))
                chunk_changed[path] = chunk_changed.get(path, False) or changed
                for name, d in diffs.items():
                    merged.setdefault(name, {}).update(d)
                merged.setdefault('ipv6_subnet', {}).update(extra.get('ipv6_subnet', {}))
                if grew:
                    base = os.path.basename(path)
                    file_hits[base] = sorted(set(file_hits.get(base, [])) | set(grew))

            for path, parts in chunk_parts.items():
                _assemble_chunks(path, parts,
                                 chunk_changed.get(path, False) and path not in chunk_failed)
        finally:
            try:
                os.unlink(ctx_path)
            except OSError:
                pass

    # IPv4 subnet/state are authoritative from the pre-pass; ipv6_subnet is
    # the union of the (deterministic, hence consistent) worker allocations.
    merged['subnet'] = frozen['subnet']
    merged['state'] = frozen['state']
    return merged, file_hits
