# parallel.py — opt-in (--jobs) process-parallel scrubbing.
#
# Why processes and not threads: the scrub phase is CPU-bound regex and Python's
# `re` holds the GIL, so threads give no speedup. Why this particular shape: the
# scrubbers are a *chained* pipeline that allocates fake values lazily, so naive
# per-file parallelism would assign the same real value different fakes in
# different workers. The safe decomposition is:
#
#   1. Serial pre-pass (here, in the parent) builds the IP/IPv6/MAC maps. IPv4
#      subnet allocation needs global coordination, so it must happen once.
#   2. Frozen dict scrubbers (hostname/domain/username/serial/keyword) are pure
#      read-only and safe as-is.
#   3. The late lazy scrubbers (email/password/cloud_token/ldap) run in workers
#      with deterministic=True so each worker independently produces the same
#      fake for the same input. Merging the per-worker dicts is then a union.
#
# The default serial path (--jobs 1) is unchanged and does not use this module.

import os
import sys
import logging
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
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger


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
        HostnameScrubber(dict(frozen.get('hostname', {}))),
        DomainScrubber(dict(frozen.get('domain', {}))),
    ]
    if include_ldap:
        chain.append(LdapDnScrubber(mappings=frozen, deterministic=deterministic))
    chain += [
        UsernameScrubber(dict(frozen.get('user', {}))),
        EmailScrubber(mappings=frozen, deterministic=deterministic),
        PasswordScrubber(mappings=frozen, deterministic=deterministic),
        CloudTokenScrubber(mappings=frozen, deterministic=deterministic),
        serial,
    ]
    return [s for s in chain if s is not None]


def _scrub_batch(payload):
    """Worker entrypoint: scrub a batch of files in place, return maps + hits."""
    batch, frozen, config, include_ldap, verbose = payload
    logger = SupportutilsScrubLogger(log_level="verbose" if verbose else "normal")
    scrubbers = _build_chain(frozen, config, deterministic=True, include_ldap=include_ldap)
    fp = FileProcessor(config, scrubbers)

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

    maps = {s.name: dict(s.mapping) for s in fp.scrubbers}
    ipv6_s = fp['ipv6']
    extra = {'ipv6_subnet': ipv6_s.subnet_map if ipv6_s else {}}
    return maps, hits, extra


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
        serial pre-pass, then fans the full chain out to workers.

    Returns (merged_mappings, file_hits).
    """
    jobs = max(1, min(jobs, len(report_files)))

    # --- Serial pre-pass: build only the IPv4 maps (no writes) -------------
    # IPv4 fake pools are small so subnet allocation needs global coordination,
    # hence a serial pass. IPv6 and MAC allocate deterministically in workers
    # (see _build_chain), so they need no pre-pass.
    ip = IPScrubber(config, mappings=frozen_seed)
    pre = FileProcessor(config, [ip], learn_only=True)
    for path in report_files:
        try:
            pre.process_file(path, logger, verbose, dry_run=True)
        except Exception as e:
            logger.error(f"pre-pass failed for {path}: {e}")

    frozen = dict(frozen_seed)
    frozen['ip'] = dict(ip.mapping)
    frozen['subnet'] = dict(ip.subnet_dict)
    frozen['state'] = dict(ip.state)
    frozen.setdefault('ipv6', dict(frozen_seed.get('ipv6', {})))
    frozen.setdefault('ipv6_subnet', dict(frozen_seed.get('ipv6_subnet', {})))
    frozen.setdefault('mac', dict(frozen_seed.get('mac', {})))

    # --- Parallel apply ----------------------------------------------------
    batches = _balanced_batches(report_files, jobs)
    payloads = [(b, frozen, config, include_ldap, verbose) for b in batches]

    merged = {k: dict(v) for k, v in frozen.items() if isinstance(v, dict)}
    file_hits = {}

    if len(batches) == 1:
        results = [_scrub_batch(payloads[0])]
    else:
        with ProcessPoolExecutor(max_workers=len(batches)) as ex:
            results = list(ex.map(_scrub_batch, payloads))

    for maps, hits, extra in results:
        for name, d in maps.items():
            merged.setdefault(name, {}).update(d)
        merged.setdefault('ipv6_subnet', {}).update(extra.get('ipv6_subnet', {}))
        file_hits.update(hits)

    # IPv4 subnet/state are authoritative from the serial pre-pass; ipv6_subnet
    # is the union of the (deterministic, hence consistent) worker allocations.
    merged['subnet'] = frozen['subnet']
    merged['state'] = frozen['state']
    return merged, file_hits
