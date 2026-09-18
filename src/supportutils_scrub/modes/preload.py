"""--preload: learn names from every input, write the shared mapping, scrub
nothing.

A multi-capture case is scrubbed one capture at a time with a shared
mapping, so the first capture is scrubbed knowing only its own names; a
peer that only a later capture names survives into the first capture's
output. This pass walks every input first (supportconfig trees, cluster
report dirs, archives, loose files), learns hostnames, domains, users,
serials and SIDs, mints the run's pseudonym key, and saves the mapping.
The per-capture scrubs that follow start with the complete name set.

Read-only on its inputs: an archive is extracted into a private temporary
directory and removed afterwards; a folder is only read.
"""

import os
import re
import shutil
import sys
import tempfile
import tarfile

from supportutils_scrub import det
from supportutils_scrub.audit import get_secure_tmp_base
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.extractor import (is_archive_path, walk_supportconfig,
                                          extract_tgz_archive)
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.pipeline import (extract_and_map_domains,
                                         extract_hostnames,
                                         extract_hostnames_from_adopted_paths,
                                         extract_usernames, extract_serials,
                                         extract_sids, is_supportconfig_folder,
                                         dataset_paths)
from supportutils_scrub.translator import Translator
from supportutils_scrub.username_scrubber import UsernameScrubber

_TEXT_SCAN_MAX = 8 << 20      # per loose/non-supportconfig file


def _tar_mode(path):
    p = path.lower()
    if p.endswith(('.txz', '.tar.xz')):
        return 'r:xz'
    if p.endswith(('.tbz', '.tbz2', '.tar.bz2')):
        return 'r:bz2'
    return 'r:gz'


def _split(value):
    return [v for v in re.split(r'[,\s;]+', value.strip()) if v] if value else []


def _text_of(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            return fh.read(_TEXT_SCAN_MAX)
    except OSError:
        return ''


def _learn_tree(tree, mappings, seeds, config=None):
    files = walk_supportconfig(tree)
    is_sc = is_supportconfig_folder(files)
    scan = files if is_sc else []
    extra_hosts = list(seeds['hostname'])
    extra_hosts.extend(extract_hostnames_from_adopted_paths(tree, config=config))
    extra_domains, extra_users = list(seeds['domain']), list(seeds['user'])
    if not is_sc:
        # a cluster report or a plain folder: no identity files, so read the
        # text itself (syslog hosts, NFS servers) as the file mode does
        for f in files:
            text = _text_of(f)
            if not text:
                continue
            extra_domains += DomainScrubber.extract_domains_from_text(text)
            extra_users += UsernameScrubber.extract_usernames_from_text(text)
            extra_hosts += HostnameScrubber.extract_hostnames_from_text(text)
    domain_dict, tld_map = extract_and_map_domains(scan, extra_domains, mappings)
    mappings['domain'] = domain_dict
    mappings['tld_map'] = tld_map
    mappings['user'] = extract_usernames(scan, extra_users, mappings)
    # all files: extract_hostnames reads only network.txt and the cluster
    # record files, and a cluster report carries those without being a
    # supportconfig
    mappings['hostname'] = extract_hostnames(files, extra_hosts, mappings,
                                             config=config)
    if is_sc:
        mappings['serial'] = extract_serials(files, mappings)
    mappings['sid'] = extract_sids(files, mappings)


def _learn_file(path, mappings, seeds, config=None):
    text = _text_of(path)
    hosts = list(seeds['hostname']) + HostnameScrubber.extract_hostnames_from_text(text)
    domains = list(seeds['domain']) + DomainScrubber.extract_domains_from_text(text)
    users = list(seeds['user']) + UsernameScrubber.extract_usernames_from_text(text)
    domain_dict, tld_map = extract_and_map_domains([], domains, mappings)
    mappings['domain'] = domain_dict
    mappings['tld_map'] = tld_map
    mappings['user'] = extract_usernames([], users, mappings)
    mappings['hostname'] = extract_hostnames([], hosts, mappings, config=config)
    mappings['sid'] = extract_sids([path], mappings)


def run_preload_mode(args, logger):
    from supportutils_scrub.audit import load_mappings_file
    from supportutils_scrub.config import DEFAULT_CONFIG_PATH
    from supportutils_scrub.config_reader import ConfigReader
    # the operator's hostname_preserve list decides what is never given a
    # mapping, and this pass is what writes the mapping file
    config = ConfigReader(DEFAULT_CONFIG_PATH).read_config(
        getattr(args, 'config', None))
    mappings = {}
    if args.mappings and os.path.exists(args.mappings):
        mappings = load_mappings_file(args.mappings)
    det.ensure_key(mappings)
    seeds = {'hostname': _split(getattr(args, 'hostname', None)),
             'domain': _split(getattr(args, 'domain', None)),
             'user': _split(getattr(args, 'username', None))}
    for kind in ('hostname', 'domain', 'user', 'serial', 'sid'):
        mappings.setdefault(kind, {})

    for path in args.supportconfig_path:
        if os.path.isdir(path):
            _learn_tree(path, mappings, seeds, config=config)
        elif os.path.isfile(path) and is_archive_path(path):
            tmp = tempfile.mkdtemp(prefix='scrub-preload-',
                                   dir=get_secure_tmp_base())
            try:
                extract_tgz_archive(path, logger, extract_base=tmp,
                                    mode=_tar_mode(path))
                _learn_tree(tmp, mappings, seeds, config=config)
            except (tarfile.TarError, OSError) as e:
                logger.warning(f"preload: cannot read {path}: {e}")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        elif os.path.isfile(path):
            _learn_file(path, mappings, seeds, config=config)
        else:
            logger.warning(f"preload: no such input {path}")

    if det.current_key():
        mappings[det.KEY_FIELD] = det.current_key()
    if args.mappings:
        out = args.mappings
    else:
        from datetime import datetime
        cfg = getattr(args, '_preloaded_config', None)
        ds = getattr(cfg, 'dataset_dir', None) or get_secure_tmp_base()
        out = dataset_paths(ds, datetime.now().strftime('%Y%m%d_%H%M%S'))[0]
    Translator.save_datasets(out, mappings)
    err = sys.stderr
    print(f"| Mapping file              : {out}", file=err)
    print(f"| Preload                   : {len(mappings['hostname'])} hostname(s), "
          f"{len(mappings['domain'])} domain(s), {len(mappings['user'])} user(s), "
          f"{len(mappings['sid'])} SID(s)", file=err)
    return out
