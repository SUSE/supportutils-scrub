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
#   3. The late lazy scrubbers (auth/email/password/cloud_token/ldap) run in workers
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
import time
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
from supportutils_scrub.auth_scrubber import AuthScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.ldap_dn_scrubber import LdapDnScrubber
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.sid_scrubber import SIDScrubber
import gzip
import subprocess
from supportutils_scrub.processor import (compressed_opener, compression_magic_ok,
                                          _SCRUB_INFO_HEADER as _HEADER,
    FileProcessor, BINARY_SA_PATTERN, BINARY_OBJ_PATTERN,
    SAR_XZ_PATTERN, SAR_PLAIN_PATTERN, _SCRUB_INFO_HEADER,
    compressed_opener,
)
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger

_BATCHES_PER_WORKER = 8   # small-file tasks per worker (verify uses 4)
_CHUNK_THRESHOLD = 32 * 1024 * 1024
_CHUNK_MIN = 8 * 1024 * 1024
# A compressed single-file log above this many bytes ON DISK is staged to a
# plain temporary file and scrubbed across the pool like any big file. Below
# it the in-worker streaming path (one task) is cheaper than the staging.
_COMPRESSED_CHUNK_THRESHOLD = 4 * 1024 * 1024
_STAGE_SUFFIX = '.scrubplain'
_STAGE_BLOCK = 8 * 1024 * 1024
_STAGE_MIN_FREE = 1 << 30          # stop staging below 1 GB free; fall back


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

    sid = SIDScrubber(mappings=frozen)
    sid.sid_dict = dict(frozen.get('sid', {}))

    # Named so the auth scrubber can delegate to them: a login it decodes out
    # of a Basic header has to land on the same pseudonym as the same identity
    # written in clear elsewhere in the capture.
    email = EmailScrubber(mappings=frozen, deterministic=deterministic)
    username = UsernameScrubber(dict(frozen.get('user', {})))
    # Ahead of the email scrubber on purpose: in a URL the userinfo and host
    # together (user@host) match an email address exactly, so if email ran
    # first it would swallow both and the login would stop being
    # distinguishable from the host it authenticates against.
    auth = AuthScrubber(mappings=frozen, deterministic=deterministic,
                        email_scrubber=email, username_scrubber=username)

    chain = [
        IPScrubber(config, mappings=frozen),
        IPv6Scrubber(config, mappings=frozen, deterministic=deterministic),
        MACScrubber(config, mappings=frozen, deterministic=deterministic),
        keyword,
        auth,
        # Email must run before hostname/domain: once the domain part is
        # rewritten the address no longer matches EMAIL_RE and the local
        # part (often firstname.lastname) would survive.
        email,
        HostnameScrubber(dict(frozen.get('hostname', {})), config=config),
        DomainScrubber(dict(frozen.get('domain', {}))),
    ]
    if include_ldap:
        chain.append(LdapDnScrubber(mappings=frozen, deterministic=deterministic))
    chain += [
        username,
        PasswordScrubber(mappings=frozen, deterministic=deterministic),
        CloudTokenScrubber(mappings=frozen, deterministic=deterministic),
        serial, sid,
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
        # Accumulate, not assign: large compressed files are streamed and
        # learn() fires once per segment of the same file.
        cidrs, tokens = self._ip.discover(text)
        prev = self.results.get(self.current)
        if prev is None:
            self.results[self.current] = (cidrs, tokens)
        else:
            prev[0].extend(cidrs)
            prev[1].extend(tokens)

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
            frozen, config, include_ldap, verbose, decompress = pickle.load(f)
        from supportutils_scrub import det as _det
        _det.set_key(frozen.get(_det.KEY_FIELD))
        logger = SupportutilsScrubLogger(log_level="verbose" if verbose else "normal")
        scrubbers = _build_chain(frozen, config, deterministic=True,
                                 include_ldap=include_ldap)
        fp = FileProcessor(config, scrubbers, decompress=decompress)
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
    times = []
    # Per-file output from process_file is noisy when interleaved; silence it.
    devnull = open(os.devnull, 'w')
    saved_stdout = sys.stdout
    sys.stdout = devnull
    try:
        for path in batch:
            before = {s.name: len(s.mapping) for s in fp.scrubbers}
            t0 = time.perf_counter()
            fp.process_file(path, logger, verbose)
            times.append((os.path.basename(path), time.perf_counter() - t0))
            grew = [name for name, prev in before.items() if len(fp[name].mapping) > prev]
            if grew:
                hits[os.path.basename(path)] = grew
    finally:
        sys.stdout = saved_stdout
        devnull.close()

    diffs, extra = _map_diffs(fp, base_keys)
    return diffs, hits, extra, times


def _scrub_chunk(payload):
    """Worker entrypoint: scrub one line-aligned byte range of a large file
    into a part file. The parent reassembles the parts in order."""
    ctx_path, path, idx, start, end = payload
    fp, base_keys, logger, verbose = _get_ctx(ctx_path)

    t0 = time.perf_counter()
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
    return (path, idx, part_path, scrubbed != text, diffs, extra, grew,
            time.perf_counter() - t0)


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


def _stageable_compressed(path):
    """(ext, opener) when this compressed log is worth staging for the pool:
    a healthy .gz/.xz/.bz2 stream (not a sar binary) above the threshold."""
    base = os.path.basename(path)
    comp = compressed_opener(base)
    if not comp or SAR_XZ_PATTERN.match(base):
        return None
    try:
        if os.path.getsize(path) <= _COMPRESSED_CHUNK_THRESHOLD:
            return None
    except OSError:
        return None
    if not compression_magic_ok(path, comp[0]):
        return None                     # misnamed: process_file handles it
    return comp


def _free_bytes(path):
    try:
        st = os.statvfs(os.path.dirname(path) or '.')
        return st.f_bavail * st.f_frsize
    except OSError:
        return None


def _stage_compressed(path, comp, logger):
    """Decompress `path` into a plain sibling temp file, streaming. Returns
    the staged path, or None (damaged stream, no space): the caller then
    leaves the file to the in-worker streaming path, which salvages.

    Measured before: a multi-GB rotated log was excluded from chunking by
    name, so it was one task on one core whatever --jobs said; at ~2 MB/s
    per core a 3.3 GB payload took 27 minutes and set every scrub's p99."""
    ext, opener = comp
    staged = path + _STAGE_SUFFIX
    try:
        with opener(path, 'rb') as src, open(staged, 'wb') as out:
            n = 0
            while True:
                block = src.read(_STAGE_BLOCK)
                if not block:
                    break
                out.write(block)
                n += 1
                if n % 32 == 0:          # every 256 MB: is there room?
                    free = _free_bytes(staged)
                    if free is not None and free < _STAGE_MIN_FREE:
                        raise OSError(f"{free >> 20} MB free; staging stopped")
    except MemoryError:
        raise
    except Exception as e:
        logger.warning(f"{os.path.basename(path)}: not staged for the pool "
                       f"({e}); scrubbed as a stream instead")
        try:
            os.remove(staged)
        except OSError:
            pass
        return None
    return staged


def _recompress(staged, path, ext, opener, logger):
    """Compress the staged plain result back into `path`, streaming, and
    prove the result is a complete stream of the format its name promises
    before it replaces the original (the write_compressed_text contract)."""
    tmp = path + '.scrubtmp'
    label = os.path.basename(path)
    try:
        size = os.path.getsize(staged)
        if ext == '.xz' and shutil.which('xz'):
            with open(staged, 'rb') as src, open(tmp, 'wb') as out:
                subprocess.run(['xz', '-T0', '-c'], stdin=src, stdout=out,
                               check=True)
        else:
            with open(staged, 'rb') as src:
                if ext == '.gz':
                    fh = open(tmp, 'wb')
                    out = gzip.GzipFile(filename=label[:-len(ext)], mode='wb',
                                        fileobj=fh)
                else:
                    fh = None
                    out = opener(tmp, 'wb')
                try:
                    shutil.copyfileobj(src, out, _STAGE_BLOCK)
                finally:
                    out.close()
                    if fh:
                        fh.close()
        read_back = 0
        with opener(tmp, 'rb') as check:
            while True:
                block = check.read(_STAGE_BLOCK)
                if not block:
                    break
                read_back += len(block)
        if read_back != size:
            raise ValueError(f"read back {read_back} of {size} bytes")
        if not compression_magic_ok(tmp, ext):
            raise ValueError(f"result is not a {ext[1:]} stream")
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.error(f"{label}: left unchanged, could not write a valid "
                     f"{ext[1:]} stream: {e}")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def _finish_staged(path, staged, ext, opener, changed, decompress, logger):
    """Put the staged result where the file belongs: plain (under --unpacked,
    when no plain sibling exists) or recompressed. The original is never
    touched when the result could not be written. The staging file is
    removed on every path."""
    plain_path = path[:-len(ext)]
    try:
        if decompress and not os.path.exists(plain_path):
            os.replace(staged, plain_path)
            os.remove(path)
            return True
        if changed:
            return _recompress(staged, path, ext, opener, logger)
        return True
    finally:
        try:
            os.remove(staged)
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
                      verbose=False, include_ldap=True, decompress=False):
    """Scrub report_files across `jobs` processes.

    frozen_seed: a mappings dict pre-populated with the globally-coordinated
        maps (hostname/domain/user/serial/keyword and any --mappings seed for
        ip/ipv6/mac/email/...). This function adds the ip/ipv6/mac maps via a
        discover/replay pre-pass, then fans the full chain out to workers.

    Returns (merged_mappings, file_hits, file_times) where file_times is
    [(basename, wall seconds)] per scrubbed file (chunked files summed).
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
        # Big compressed logs are staged plain and chunked like any big file.
        staged_map = {}          # staged path -> (original, ext, opener)
        work_files = []
        for p in report_files:
            comp = _stageable_compressed(p)
            st = _stage_compressed(p, comp, logger) if comp else None
            if st:
                staged_map[st] = (p, comp[0], comp[1])
                work_files.append(st)
            else:
                work_files.append(p)
        report_files = work_files

        def _big(p):
            return p in staged_map or _is_chunkable(p)

        disc_big = [p for p in report_files if _big(p)]
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
        from supportutils_scrub import det as _det
        if _det.current_key():
            frozen[_det.KEY_FIELD] = _det.current_key()
        frozen['ip'] = dict(ip.mapping)
        frozen['subnet'] = dict(ip.subnet_dict)
        frozen['state'] = dict(ip.state)
        frozen.setdefault('ipv6', dict(frozen_seed.get('ipv6', {})))
        frozen.setdefault('ipv6_subnet', dict(frozen_seed.get('ipv6_subnet', {})))
        frozen.setdefault('mac', dict(frozen_seed.get('mac', {})))

        # --- Parallel apply --------------------------------------------------
        big_files = [p for p in report_files if _big(p)]
        big_set = set(big_files)
        small_files = [p for p in report_files if p not in big_set]

        fd, ctx_path = tempfile.mkstemp(prefix='supportutils-scrub-ctx-', suffix='.pkl')
        merged = {k: dict(v) for k, v in frozen.items() if isinstance(v, dict)}
        file_hits = {}
        file_times = []
        chunk_times = {}  # path -> summed chunk seconds
        try:
            # mkstemp = mode 0600; the file holds real->fake mappings.
            with os.fdopen(fd, 'wb') as f:
                pickle.dump((frozen, config, include_ldap, verbose, decompress), f,
                            protocol=pickle.HIGHEST_PROTOCOL)

            # The critical path first: the chunks of the biggest files go in
            # before any small-file batch, or the pool (FIFO) hands every
            # worker a batch and the longest work waits for a free slot.
            chunk_parts = {}    # path -> [(idx, part_path)]
            chunk_changed = {}  # path -> bool
            chunk_failed = set()
            chunk_futures = []
            for path in big_files:
                for idx, (start, end) in enumerate(_chunk_bounds(path, jobs)):
                    chunk_futures.append(
                        (path, ex.submit(_scrub_chunk, (ctx_path, path, idx, start, end))))

            # Many more tasks than workers: cost is content-dependent, not
            # byte-proportional (identical-size chunks measured at 2 min and
            # 80 min), so `jobs` byte-balanced buckets left the slowest bucket
            # setting the phase while the other workers idled. The per-task
            # overhead is a dict diff; the context is cached per worker.
            futures = []
            for batch in _balanced_batches(small_files, jobs * _BATCHES_PER_WORKER):
                futures.append(ex.submit(_scrub_batch, (ctx_path, batch)))

            for fut in futures:
                diffs, hits, extra, times = fut.result()
                for name, d in diffs.items():
                    merged.setdefault(name, {}).update(d)
                merged.setdefault('ipv6_subnet', {}).update(extra.get('ipv6_subnet', {}))
                file_hits.update(hits)
                file_times.extend(times)

            for fut_path, fut in chunk_futures:
                try:
                    path, idx, part_path, changed, diffs, extra, grew, secs = fut.result()
                except Exception as e:
                    # Same failure mode as the serial path: the file is left
                    # unscrubbed. Log loudly and skip its assembly.
                    logger.error(f"chunk scrub failed for {fut_path}: {e}")
                    chunk_failed.add(fut_path)
                    continue
                chunk_parts.setdefault(path, []).append((idx, part_path))
                chunk_changed[path] = chunk_changed.get(path, False) or changed
                chunk_times[path] = chunk_times.get(path, 0.0) + secs
                for name, d in diffs.items():
                    merged.setdefault(name, {}).update(d)
                merged.setdefault('ipv6_subnet', {}).update(extra.get('ipv6_subnet', {}))
                if grew:
                    base = os.path.basename(path)
                    file_hits[base] = sorted(set(file_hits.get(base, [])) | set(grew))

            for path, parts in chunk_parts.items():
                _assemble_chunks(path, parts,
                                 chunk_changed.get(path, False) and path not in chunk_failed)
            for st, (orig, ext, opener) in staged_map.items():
                if st in chunk_failed:
                    continue             # original left untouched; staging removed below
                _finish_staged(orig, st, ext, opener,
                               chunk_changed.get(st, False), decompress, logger)
        finally:
            for st in staged_map:
                try:
                    os.remove(st)
                except OSError:
                    pass
            try:
                os.unlink(ctx_path)
            except OSError:
                pass

    for path, secs in chunk_times.items():
        name = os.path.basename(staged_map[path][0] if path in staged_map else path)
        file_times.append((name, secs))

    # IPv4 subnet/state are authoritative from the pre-pass; ipv6_subnet is
    # the union of the (deterministic, hence consistent) worker allocations.
    merged['subnet'] = frozen['subnet']
    merged['state'] = frozen['state']
    return merged, file_hits, file_times
