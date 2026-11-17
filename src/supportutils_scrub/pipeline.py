# pipeline.py — shared extraction, mapping, and scrubber-init helpers

from supportutils_scrub.processor import _iter_line_segments, compressed_opener
import os
import sys
import re
import time
import logging
import shutil
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber, is_preserved_domain
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.audit import load_mappings_file


def warn_private_ip(config, file=None):
    out = file or sys.stdout
    if not config.obfuscate_private_ip:
        print("[!] WARNING: Private IP obfuscation is DISABLED.", file=out)
        print("    Only public IP addresses will be obfuscated.", file=out)
        print(f"    To also obfuscate private IPs (10.x, 172.16.x, 192.168.x),", file=out)
        print(f"    set 'obfuscate_private_ip = yes' in {DEFAULT_CONFIG_PATH}", file=out)
        print(file=out)


#: the pseudonyms a new mapping hands out (host-1, user1, dom1.<tld>); a
#: mapping that already holds the older forms keeps them, so one case never
#: mixes two. host-N because the kernel names SCSI adapters host0, host1 ...
#: and dom from 1 because Xen calls its control domain dom0.
_FORMS = {'hostname': ('host-{}', 'hostname_{}', re.compile(r'^hostname_\d+$')),
          'user': ('user{}', 'user_{}', re.compile(r'^user_\d+$')),
          'domain': ('dom{}', 'domain_{}', re.compile(r'^domain_\d+\.'))}


def _known(mappings):
    """Every real name and every pseudonym the mapping holds, lower case."""
    out = set()
    for name, sec in (mappings or {}).items():
        if isinstance(sec, dict):
            for k, v in sec.items():
                out.add(str(k).lower())
                out.add(str(v).lower())
                # dom1 of dom1.aaa is what a DN shows (DC=dom1): a later
                # dom1.aab would read as the same domain there
                if name == 'domain':
                    out.add(str(v).split('.', 1)[0].lower())
    return out


class _Pseudonyms:
    """Hands out the next pseudonym of one kind. It is never a name or a
    pseudonym the mapping already knows (a host really called host-3 makes
    the counter skip 3), and a number is never handed out twice. A mapping
    that holds the older forms in any of the three kinds keeps the older
    forms for all of them."""

    def __init__(self, kind, section, mappings):
        new, old, _old_re = _FORMS[kind]
        legacy = any(_FORMS[k][2].match(str(v))
                     for k in _FORMS
                     for sec in ((mappings or {}).get(k) or {}, section if k == kind else {})
                     if isinstance(sec, dict) for v in sec.values())
        self.form = old if legacy else new
        # the older forms counted from the section size; kept, so a case
        # scrubbed before keeps numbering as it did
        self.n = len(section) if legacy else 1
        self.known = _known(mappings) | {str(k).lower() for k in section} \
            | {str(v).lower() for v in section.values()}

    def reserve(self, names):
        """The real names this run is about to map: none becomes a pseudonym."""
        self.known.update(str(n).lower() for n in names)

    def next(self, suffix=''):
        while True:
            base = self.form.format(self.n)
            self.n += 1
            if base.lower() not in self.known and (base + suffix).lower() not in self.known:
                self.known.add(base.lower())
                self.known.add((base + suffix).lower())
                return base


def _next_fake_tld(counter):
    letters = 'abcdefghijklmnopqrstuvwxyz'
    a, b, c = counter // 676, (counter // 26) % 26, counter % 26
    return letters[a] + letters[b] + letters[c]


def build_hierarchical_domain_map(all_domains, existing_mappings):
    valid_domains = {d for d in all_domains
                     if '.' in d and not is_preserved_domain(d)}
    # label count first (parents before children), then the name: a tie
    # that fell back to set order varied with the per-process hash seed
    sorted_domains = sorted(valid_domains, key=lambda d: (len(d.split('.')), d))

    domain_dict = existing_mappings.get('domain', {})
    tld_map = existing_mappings.get('tld_map', {})
    names = _Pseudonyms('domain', domain_dict, existing_mappings)
    names.reserve(sorted_domains)
    # sub-domain pseudonyms continue past those the mapping holds: a fresh
    # count per run gave two sub-domains one pseudonym
    used_subs = {str(v).lower() for v in domain_dict.values()}
    sub_domain_counter = 0
    # an older mapping's entry for a preserved domain is dropped here, so it
    # is not saved again; its pseudonym stays reserved for this run above
    for d in [d for d in domain_dict if is_preserved_domain(d)]:
        del domain_dict[d]

    for domain in sorted_domains:
        if domain in domain_dict:
            continue
        parts = domain.split('.')
        parent_domain = '.'.join(parts[1:])

        if parent_domain in domain_dict:
            while f"sub_{sub_domain_counter}.{domain_dict[parent_domain]}".lower() in used_subs:
                sub_domain_counter += 1
            domain_dict[domain] = f"sub_{sub_domain_counter}.{domain_dict[parent_domain]}"
            used_subs.add(domain_dict[domain].lower())
            sub_domain_counter += 1
        else:
            real_tld = parts[-1].lower()
            if real_tld not in tld_map:
                tld_map[real_tld] = _next_fake_tld(len(tld_map))
            fake_tld = tld_map[real_tld]
            domain_dict[domain] = f"{names.next('.' + fake_tld)}.{fake_tld}"

    return domain_dict, tld_map


def extract_and_map_domains(report_files, additional_domains, mappings):
    all_domains = set()
    for domain in additional_domains:
        if is_preserved_domain(domain):
            logging.warning(f"--domain {domain}: a SUSE or cloud metadata "
                            "domain is never scrubbed; use --keywords to "
                            "scrub it anyway")
        DomainScrubber._add_domain_and_parents(domain, all_domains)

    files_to_scan = {
        'network.txt': ['# /etc/hosts', '# /etc/resolv.conf', '# /bin/nmcli', '# /usr/bin/nmcli'],
        'nfs.txt': ['# /bin/egrep'],
        'ntp.txt': ['# /etc/ntp.conf', '# /etc/chrony.conf'],
        'sssd.txt': ['# /etc/sssd/sssd.conf'],
    }
    # Authoritative domain declarations: exempt from the public-TLD whitelist
    # so internal TLDs (e.g. .rz) are learned too.
    trusted_sections = {'# /etc/hosts', '# /etc/resolv.conf'}
    for file_path in report_files:
        basename = os.path.basename(file_path)
        if basename in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for section in files_to_scan[basename]:
                        domains = DomainScrubber.extract_domains_from_file_section(
                            f, section, trusted=section in trusted_sections)
                        all_domains.update(domains)
            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")

    return build_hierarchical_domain_map(all_domains, mappings)


def extract_hostnames(report_files, additional_hostnames, mappings, config=None):
    # Preserved product strings (uyuni-server family, loopback names, the
    # cloud metadata aliases) are dropped HERE, at the single source of the
    # working dict: a legacy mapping file recorded before the preserve rule
    # existed must not resurrect them, in text scrubbing OR in file/dir
    # renaming. The config carries the operator's own hostname_preserve
    # list, which is worth nothing if it does not reach this point.
    from supportutils_scrub.hostname_scrubber import preserved_hostnames
    _preserved = preserved_hostnames(config)
    raw = mappings.get('hostname', {})
    hostname_dict = {k: v for k, v in raw.items()
                     if k.strip() and k.lower() not in _preserved}
    names = _Pseudonyms('hostname', raw, mappings)
    all_hostnames = []

    for f in report_files:
        if 'network.txt' in f:
            all_hostnames.extend(HostnameScrubber.extract_hostnames_from_hosts(f))
            all_hostnames.extend(HostnameScrubber.extract_hostnames_from_hostname_section(f))
        # A clustered system knows the names of hosts it did not capture. Those
        # names appear nowhere in this node's own identity files, so without
        # this they are never learned and survive into the scrubbed output.
        base = os.path.basename(f)
        if base.startswith(('ha.txt', 'cib.xml', 'crm_mon', 'members.txt',
                            'corosync.conf')):
            all_hostnames.extend(
                HostnameScrubber.extract_hostnames_from_cluster(f))

    all_hostnames.extend(additional_hostnames)
    names.reserve(all_hostnames)
    # the scrub matches case-insensitively, so WEB01 is the host web01 is
    known = {k.lower(): v for k, v in hostname_dict.items()}
    for h in all_hostnames:
        # however a name arrived here -- harvested, seeded with --hostname, or
        # carried in from an older mapping file -- a preserved one is never
        # given a mapping, because a mapping is what renames files later.
        if not h.strip() or h.lower() in _preserved or h.lower() in known:
            continue
        # a dotted name shares its short label's pseudonym, so a directory
        # named by FQDN and the bare host in the text read as one host
        short = h.split('.', 1)[0]
        if short != h and _plausible_hostname(short, _preserved):
            if short.lower() not in known:
                hostname_dict[short] = known[short.lower()] = names.next()
            hostname_dict[h] = known[h.lower()] = known[short.lower()]
        else:
            hostname_dict[h] = known[h.lower()] = names.next()
    return hostname_dict


# Collector-adoption bypass fix: node identities carried by DIRECTORY
# STRUCTURE never reach hostname_dict when they are absent from the primary
# host's network.txt (crm_report per-node dirs, nested supportconfigs whose
# hosts file does not list themselves). Confirmed leaks twice in the field:
# a crm_report node dir and an adopted MLM supportconfig both kept the real
# customer FQDN in their directory name while file contents were scrubbed.
_NODE_DIR_MARKERS = ("sysinfo.txt", "cib.xml", "ha-log.txt", "pengine")
_SCC_DIR_RE = re.compile(r"^scc_([A-Za-z][A-Za-z0-9._-]*?)(?:_\d{6}[_\d]*)?$")
_UNAME_LINE_RE = re.compile(r"^Linux\s+([A-Za-z][A-Za-z0-9._-]*)", re.M)


def _plausible_hostname(name, preserved):
    return (len(name) >= 3 and any(c.isalpha() for c in name)
            and name.lower() not in preserved
            and not name.lower().endswith((".txt", ".log", ".xml", ".gz")))


def extract_hostnames_from_adopted_paths(root, config=None):
    """Harvest node names from tree STRUCTURE: crm_report node dirs (the dir
    basename IS the node name), nested scc_<host>_<stamp> dirs, and every
    nested basic-environment.txt uname line. For dotted names the short first
    label is harvested too, so bare-shortname mentions map consistently."""
    from supportutils_scrub.hostname_scrubber import preserved_hostnames
    preserved = preserved_hostnames(config)
    found = []

    def _add(name):
        if _plausible_hostname(name, preserved):
            found.append(name)
            if "." in name:
                short = name.split(".", 1)[0]
                if _plausible_hostname(short, preserved):
                    found.append(short)

    for base, dirs, files in os.walk(root):
        fset = set(files) | set(dirs)
        if any(m in fset for m in _NODE_DIR_MARKERS):
            _add(os.path.basename(base))
        for d in dirs:
            m = _SCC_DIR_RE.match(d)
            if m:
                _add(m.group(1))
        if "basic-environment.txt" in files:
            try:
                with open(os.path.join(base, "basic-environment.txt"),
                          encoding="utf-8", errors="ignore") as fh:
                    m = _UNAME_LINE_RE.search(fh.read(65536))
                if m:
                    _add(m.group(1))
            except OSError:
                pass
    # longest first so FQDNs map before their short forms
    return sorted(set(found), key=len, reverse=True)


def extract_usernames(report_files, additional_usernames, mappings):
    username_dict = mappings.get('user', {})
    for k in [k for k in username_dict if not k.strip()]:
        del username_dict[k]
    names = _Pseudonyms('user', username_dict, mappings)
    all_usernames = []

    msg_files = {'messages.txt', 'security-apparmor.txt', 'sssd.txt'}
    for f in report_files:
        base = os.path.basename(f)
        if 'pam.txt' in f:
            sections = ['# /usr/bin/getent passwd', '# /etc/passwd']
            all_usernames.extend(UsernameScrubber.extract_usernames_from_section(f, sections))
        elif base in msg_files:
            all_usernames.extend(UsernameScrubber.extract_usernames_from_messages(f))

    all_usernames.extend(additional_usernames)
    names.reserve(all_usernames)
    known = {k.lower() for k in username_dict}
    for u in all_usernames:
        if u.strip() and u.lower() not in known:
            known.add(u.lower())
            username_dict[u] = names.next()
    return username_dict


#: Pre-scans read in line-aligned segments of this size: every discovery
#: pattern matches within one line, and a multi-hundred-MB pacemaker.log no
#: longer lands whole in the parent's memory.
_PRESCAN_SEG_BYTES = 32 * 1024 * 1024


def _pre_scan_file(scrubber, fpath):
    try:
        with open(fpath, 'rb') as f:
            for seg in _iter_line_segments(f.read, _PRESCAN_SEG_BYTES):
                scrubber.pre_scan(seg.decode('utf-8', 'ignore'))
    except MemoryError:
        raise
    except Exception:
        pass


def extract_serials(report_files, mappings, config=None):
    if config is not None and not getattr(config, 'obfuscate_serial', True):
        return dict(mappings.get('serial', {}))
    scrubber = SerialScrubber(mappings=mappings)
    target_files = {'basic-environment.txt', 'boot.txt', 'hardware.txt'}
    for fpath in report_files:
        if os.path.basename(fpath) in target_files:
            _pre_scan_file(scrubber, fpath)
    return scrubber.serial_dict


def extract_sids(report_files, mappings):
    """Discover SAP System IDs from SAP/HA-relevant files. Discovery patterns are
    SAP-specific so scanning a broad set is safe; the scrub pass then substitutes the
    SID across ALL files. Not gated on is_sc -- crm_reports leak rsc_SAP_<SID> too."""
    from supportutils_scrub.sid_scrubber import SIDScrubber
    scrubber = SIDScrubber(mappings=mappings)
    named = {'basic-environment.txt', 'ha.txt', 'systemd.txt', 'ps.txt',
             'fs-diskio.txt', 'open-files.txt', 'cib.xml', 'pacemaker.log'}

    def _relevant(name):
        n = name.lower()
        return n in named or 'sap' in n or 'crm' in n or 'hana' in n or 'pacemaker' in n
    for fpath in report_files:
        if _relevant(os.path.basename(fpath)):
            _pre_scan_file(scrubber, fpath)
    return scrubber.sid_dict


def _keyword_file(args, config):
    if args.keyword_file:
        return args.keyword_file
    path = getattr(config, 'key_words_file', None)
    if not getattr(config, 'use_key_words_file', False) or not path:
        return None
    if os.path.isfile(path):
        return path
    # the shipped config enables this with a path most hosts do not have,
    # so the warning stays off stdout (--quiet prints only the output path)
    print(f"[!] key_words_file not found: {path} (use_key_words_file is set)",
          file=sys.stderr)
    return None


def init_scrubbers(args, config, logger):
    mappings = {}
    if args.mappings:
        mappings = load_mappings_file(args.mappings)
    from supportutils_scrub import det as _det
    _det.ensure_key(mappings)

    cmd_keywords = []
    if args.keywords:
        cmd_keywords = [kw.strip() for kw in re.split(r'[,\s;]+', args.keywords.strip()) if kw.strip()]

    # The mapping's keywords keep their pseudonyms; only new ones are numbered.
    try:
        keyword_scrubber = KeywordScrubber(keyword_file=_keyword_file(args, config),
                                           cmd_keywords=list(dict.fromkeys(cmd_keywords)),
                                           mappings=mappings)
        if not keyword_scrubber.is_loaded():
            keyword_scrubber = None
    except Exception as e:
        logger.error(f"Failed to initialize KeywordScrubber: {e}")
        keyword_scrubber = None

    try:
        ip_scrubber = IPScrubber(config, mappings=mappings)
        mac_scrubber = MACScrubber(config, mappings=mappings)
        ipv6_scrubber = IPv6Scrubber(config, mappings=mappings)
    except Exception as e:
        logger.error(f"Error initializing scrubbers: {e}")
        sys.exit(1)

    return mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber


def split_names(value):
    return re.split(r'[,\s;]+', value) if value else []


def chain_seed(mappings, hostname_dict, domain_dict, username_dict,
               serial_dict, sid_dict, keyword_scrubber):
    """The mappings plus this run's learned dicts: what build_chain needs."""
    seed = dict(mappings)
    seed.update(hostname=hostname_dict, domain=domain_dict, user=username_dict,
                serial=serial_dict, sid=sid_dict,
                keyword=keyword_scrubber.keyword_dict if keyword_scrubber else {})
    return seed


def build_chain(seed, config, deterministic=False, include_ldap=True):
    """The scrubber chain every mode runs, serial or --jobs, in this order."""
    from supportutils_scrub.sid_scrubber import SIDScrubber
    from supportutils_scrub.email_scrubber import EmailScrubber
    from supportutils_scrub.auth_scrubber import AuthScrubber
    from supportutils_scrub.password_scrubber import PasswordScrubber
    from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
    from supportutils_scrub.ldap_dn_scrubber import LdapDnScrubber

    keyword = None
    if seed.get('keyword'):
        keyword = KeywordScrubber(mappings={'keyword': seed['keyword']})

    serial = None
    if getattr(config, 'obfuscate_serial', True):
        serial = SerialScrubber(mappings=seed)
        serial.serial_dict = dict(seed.get('serial') or {})

    sid = SIDScrubber(mappings=seed)
    sid.sid_dict = dict(seed.get('sid') or {})

    # Named so the auth scrubber can delegate to them: a login it decodes out
    # of a Basic header has to land on the same pseudonym as the same identity
    # written in clear elsewhere in the capture.
    email = EmailScrubber(mappings=seed, deterministic=deterministic)
    username = UsernameScrubber(dict(seed.get('user') or {}))
    # Ahead of the email scrubber on purpose: in a URL the userinfo and host
    # together (user@host) match an email address exactly, so if email ran
    # first it would swallow both and the login would stop being
    # distinguishable from the host it authenticates against.
    auth = AuthScrubber(mappings=seed, deterministic=deterministic,
                        email_scrubber=email, username_scrubber=username)

    chain = [
        IPScrubber(config, mappings=seed),
        IPv6Scrubber(config, mappings=seed, deterministic=deterministic),
        MACScrubber(config, mappings=seed, deterministic=deterministic),
        keyword,
        auth,
        # Email must run before hostname/domain: once the domain part is
        # rewritten the address no longer matches EMAIL_RE and the local
        # part (often firstname.lastname) would survive.
        email,
        HostnameScrubber(dict(seed.get('hostname') or {}), config=config),
        DomainScrubber(dict(seed.get('domain') or {})),
    ]
    if include_ldap:
        chain.append(LdapDnScrubber(mappings=seed, deterministic=deterministic))
    chain += [
        username,
        PasswordScrubber(mappings=seed, deterministic=deterministic),
        CloudTokenScrubber(mappings=seed, deterministic=deterministic),
        serial, sid,
    ]
    return [s for s in chain if s is not None]


def merge_state(*states):
    """Pool cursors: a later one wins, an empty one never wipes a loaded one."""
    out = {}
    for st in states:
        out.update(st or {})
    return out


def chain_mappings(scrubbers, base, tld_map=None):
    """The mapping a run saves: what it started from plus what the chain
    holds now. A section the chain did not run this time (serial with
    obfuscate_serial = no, ldap) is kept as loaded."""
    from supportutils_scrub import det as _det
    by_name = {s.name: s for s in scrubbers}
    out = dict(base)
    for s in scrubbers:
        out[s.name] = dict(s.mapping)
    ip_s, v6_s = by_name.get('ip'), by_name.get('ipv6')
    if ip_s is not None:
        out['subnet'] = dict(ip_s.subnet_dict)
    if v6_s is not None:
        out['ipv6_subnet'] = v6_s.subnet_map
    out['state'] = merge_state(base.get('state'), getattr(ip_s, 'state', None),
                               getattr(v6_s, 'state', None))
    if tld_map is not None:
        out['tld_map'] = tld_map
    if _det.current_key():
        out[_det.KEY_FIELD] = _det.current_key()
    return out


def drop_unscrubbed(failed, root, copied=True, file=None):
    """Remove the files a run could not scrub so they never ship raw.

    Returns False when one could not be removed, or when the tree is the
    user's own input (re-scrubbed in place), where nothing is deleted."""
    if not failed:
        return True
    out = file or sys.stderr
    ok = copied
    if copied:
        print(f"[!] {len(failed)} file(s) could not be scrubbed and were "
              f"removed from the output:", file=out)
    else:
        print(f"[!] {len(failed)} file(s) could not be scrubbed; the input was "
              f"scrubbed in place, so they were left as they are - do not share it:",
              file=out)
    for path in failed:
        if copied and os.path.lexists(path):
            try:
                os.remove(path)
            except OSError as e:
                print(f"      could not remove it: {e}", file=out)
                ok = False
        print(f"      {os.path.relpath(path, root)}", file=out)
    return ok


_PCAP_MAGIC = {b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1',     # pcap, usec
               b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1',     # pcap, nsec
               b'\x0a\x0d\x0d\x0a'}                          # pcapng


def is_pcap(path):
    try:
        with open(path, 'rb') as f:
            return f.read(4) in _PCAP_MAGIC
    except OSError:
        return False


class PhaseTimer:
    """Wall-clock time per pipeline phase. The one-line summary shows where
    a run actually spends its time: only the scrub (and verify) phases scale
    with --jobs; extract/copy/pre-scan/repack are serial and bound the total
    no matter how many workers are configured.

    With echo=True (--verbose) each mark is printed to stderr as it happens,
    so a stalled run shows which phase it is stuck in."""

    def __init__(self, echo=False):
        self._t0 = time.perf_counter()
        self._start = self._t0
        self.phases = []
        self.echo = echo

    def mark(self, name):
        now = time.perf_counter()
        self.phases.append((name, now - self._t0))
        self._t0 = now
        if self.echo:
            print(f"[i] {name}: {self.phases[-1][1]:.1f}s (elapsed {now - self._start:.1f}s)",
                  file=sys.stderr)

    def summary(self):
        total = sum(s for _, s in self.phases)
        parts = [f"{n} {s:.1f}s" for n, s in self.phases if s >= 0.05]
        parts.append(f"total {total:.1f}s")
        return "[i] Phase times: " + " | ".join(parts)

    def table(self):
        """Multi-line phase breakdown with shares and peak memory (--verbose)."""
        total = sum(s for _, s in self.phases) or 1e-9
        lines = ["", " Phase performance", " " + "-" * 38,
                 f" {'phase':<16}{'seconds':>10}{'share':>10}",
                 " " + "-" * 38]
        for name, secs in self.phases:
            lines.append(f" {name:<16}{secs:>10.1f}{100 * secs / total:>9.1f}%")
        lines.append(" " + "-" * 38)
        lines.append(f" {'total':<16}{total:>10.1f}")
        try:
            import resource
            rss_self = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
            rss_kids = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024
            lines.append(f" peak memory: {rss_self:.0f} MB main"
                         f" / {rss_kids:.0f} MB largest child (workers, xz)")
        except Exception:
            pass
        lines.append("")
        return "\n".join(lines)


def slowest_files_report(file_times, top=10):
    """Lines naming the files the scrub phase spent the most time on
    (--verbose). file_times: [(basename, seconds)]."""
    worst = sorted(file_times, key=lambda x: x[1], reverse=True)[:top]
    worst = [(base, secs) for base, secs in worst if secs >= 0.1]
    if not worst:
        return ""
    lines = ["[i] Slowest files (scrub):"]
    for base, secs in worst:
        lines.append(f"      {secs:>8.2f}s  {base}")
    return "\n".join(lines)


def report_format_mismatches(root, file=None):
    """Check the scrubbed tree for names that lie about their content and warn.

    Postcondition of every run: no file carries a .gz/.xz/.bz2 extension its
    content does not match, so a consumer that follows the extension can always
    read it. Scrubbing never creates such a file (see
    processor.FileProcessor._process_compressed); this catches the leftovers —
    a mismatch whose honest name was already taken, or a rewrite we refused."""
    from supportutils_scrub.processor import find_format_mismatches
    out = file or sys.stderr
    bad = find_format_mismatches(root)
    if not bad:
        return 0
    print(f"[!] FORMAT: {len(bad)} file(s) carry a compression extension their "
          f"content does not match:", file=out)
    for path, ext in bad[:10]:
        print(f"      {os.path.relpath(path, root)} (not a {ext[1:]} stream)", file=out)
    if len(bad) > 10:
        print(f"      ... and {len(bad) - 10} more", file=out)
    return len(bad)


def name_scrubber(hostname_dict, domain_dict=None, config=None):
    """The callable that renames one file or directory.

    A name gets EXACTLY the rules the content gets: the same two scrubbers,
    in the chain's order, so a name cannot be rewritten by something the
    text would have left alone. The plain str.replace this used to do had no
    boundaries, so a host called 'work' turned network.txt into
    nethostname_9.txt, and it was case-sensitive, so MYHOST_logs kept a name
    the content no longer used. Both scrubbers are built once per tree walk:
    each compiles a regex, which is not something to repeat per file.
    """
    from supportutils_scrub.hostname_scrubber import HostnameScrubber
    from supportutils_scrub.domain_scrubber import DomainScrubber
    hs = HostnameScrubber(hostname_dict or {}, config=config)
    ds = DomainScrubber(domain_dict) if domain_dict else None

    def scrub(name):
        name = hs.scrub(name)
        if ds is not None:
            name = ds.scrub(name)
        return name

    return scrub


def scrub_name(name, hostname_dict, domain_dict=None, config=None):
    """One name, for callers that rename a single artifact."""
    return name_scrubber(hostname_dict, domain_dict, config)(name)


def dataset_paths(dataset_dir, timestamp, hostname_dict=None, input_name=None, report=False):
    host_tag = ''
    if hostname_dict and input_name:
        for real, fake in sorted(hostname_dict.items(), key=lambda x: len(x[0]), reverse=True):
            short = real.split('.')[0]
            if real in input_name or short in input_name:
                host_tag = f"_{fake}"
                break
    base = f"obfuscation{host_tag}_{timestamp}"
    mapping_path = os.path.join(dataset_dir, f"{base}_mappings.json")
    audit_path   = os.path.join(dataset_dir, f"{base}_audit.json")
    report_path  = os.path.join(dataset_dir, f"{base}_report.json") if report else None
    return mapping_path, audit_path, report_path


def rename_extraction_paths(clean_folder_path, hostname_dict, rename_top=True,
                            domain_dict=None, config=None, renames=None):
    """Rename every path a scrubbed name changes, and record what changed.

    `renames` is an optional list the caller passes in to receive (old, new)
    pairs, relative to the tree where that reads naturally: a rename that is
    never reported leaves the operator looking for a file the output no
    longer has under that name.
    """
    if not hostname_dict and not domain_dict:
        return clean_folder_path
    scrub_one = name_scrubber(hostname_dict, domain_dict, config)

    def note(root, old, new):
        if renames is None:
            return
        rel = os.path.relpath(root, clean_folder_path)
        prefix = "" if rel == "." else rel + os.sep
        renames.append((prefix + old, prefix + new))

    def free(root, name):
        # testhost.log and TESTHOST.log both scrub to host-1.log; a plain
        # rename would overwrite one with the other
        if not os.path.lexists(os.path.join(root, name)):
            return name
        comp = compressed_opener(name)
        tail = comp[0] if comp else ''
        stem, ext = os.path.splitext(name[:len(name) - len(tail)])
        n = 1
        while os.path.lexists(os.path.join(root, f"{stem}_{n}{ext}{tail}")):
            n += 1
        return f"{stem}_{n}{ext}{tail}"

    for root, dirs, files in os.walk(clean_folder_path, topdown=True):
        # dirs must be updated in place or the walk descends into the old
        # (renamed-away) path and silently skips everything below it.
        for i, d in enumerate(dirs):
            scrubbed = scrub_one(d)
            if scrubbed != d:
                scrubbed = free(root, scrubbed)
                try:
                    os.rename(os.path.join(root, d), os.path.join(root, scrubbed))
                    note(root, d, scrubbed)
                    dirs[i] = scrubbed
                except Exception as e:
                    print(f"[!] Could not rename directory '{d}': {e}", file=sys.stderr)
        for f in files:
            scrubbed = scrub_one(f)
            if scrubbed != f:
                scrubbed = free(root, scrubbed)
                try:
                    os.rename(os.path.join(root, f), os.path.join(root, scrubbed))
                    note(root, f, scrubbed)
                except Exception as e:
                    print(f"[!] Could not rename file '{f}': {e}", file=sys.stderr)
    if not rename_top:
        return clean_folder_path
    parent   = os.path.dirname(clean_folder_path)
    basename = os.path.basename(clean_folder_path)
    scrubbed_basename = scrub_one(basename)
    if scrubbed_basename != basename:
        new_path = os.path.join(parent, scrubbed_basename)
        try:
            if os.path.exists(new_path):
                shutil.rmtree(new_path)
            os.rename(clean_folder_path, new_path)
            return new_path
        except Exception as e:
            print(f"[!] Could not rename extraction folder: {e}", file=sys.stderr)
    return clean_folder_path


def is_supportconfig_folder(file_list):
    basenames = {os.path.basename(f) for f in file_list}
    return 'basic-environment.txt' in basenames
