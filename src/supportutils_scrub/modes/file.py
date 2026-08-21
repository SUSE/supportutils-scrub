import os
import sys
import re
import json
import shutil
from datetime import datetime

from supportutils_scrub.main import SCRIPT_VERSION
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.auth_scrubber import AuthScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.ldap_dn_scrubber import LdapDnScrubber
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.sid_scrubber import SIDScrubber
from supportutils_scrub.processor import (
    FileProcessor, compressed_opener, scrubbed_output_name,
    strip_compression_ext, compression_magic_ok, looks_binary,
    _iter_line_segments, _SEG_BYTES, _TEXT_PROBE,
)
from supportutils_scrub.pipeline import (
    warn_private_ip, init_scrubbers, scrub_name,
    extract_and_map_domains, extract_hostnames, extract_usernames,
    dataset_paths,
    extract_serials, extract_sids,
)
from supportutils_scrub.audit import (
    save_mappings, print_enc_note, sha256_file, audit_record, write_audit_log,
)


def run_file_mode(args, logger):
    verbose_flag = args.verbose
    input_path = args.supportconfig_path[0]
    comp = compressed_opener(os.path.basename(input_path))
    drop_ext = False

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    config = args._preloaded_config
    dataset_path, audit_path, _ = dataset_paths(config.dataset_dir, timestamp)
    warn_private_ip(config)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    # Cheap streaming checks before anything is read whole or copied: a
    # payload that is not text is refused up front; a name that lies about
    # the content is scrubbed as the plain text it really is and the
    # misleading extension is dropped from the output name.
    if comp:
        ext, opener = comp
        if not compression_magic_ok(input_path, ext):
            if looks_binary(input_path):
                print(f"[!] {os.path.basename(input_path)}: neither a {ext[1:]} "
                      f"stream nor text — nothing to scrub")
                sys.exit(1)
            print(f"[!] {os.path.basename(input_path)}: not a {ext[1:]} stream despite "
                  f"the extension — scrubbed as plain text")
            drop_ext, comp = True, None
        else:
            try:
                with opener(input_path, 'rb') as f:
                    head = f.read(_TEXT_PROBE)
            except MemoryError:
                raise
            except Exception:
                head = b''  # damaged head; the salvage path decides later
            if b'\x00' in head:
                print(f"[!] {os.path.basename(input_path)}: {ext[1:]} payload is not "
                      f"text — nothing to scrub")
                sys.exit(1)

    additional_domains = list(re.split(r'[,\s;]+', args.domain) if args.domain else [])
    additional_usernames = list(re.split(r'[,\s;]+', args.username) if args.username else [])
    additional_hostnames = list(re.split(r'[,\s;]+', args.hostname) if args.hostname else [])

    if comp:
        # Pre-scan the payload segment by segment: a small .xz can hide a
        # multi-GB log (28:1 has been seen in the field), so it is never
        # decompressed into one string. Syslog hostname counts accumulate
        # across segments so the >=3-occurrences threshold sees the whole
        # document, same as a whole-text scan would.
        ext, opener = comp
        syslog_counts = {}

        def _read_or_stop(f):
            def _read(n):
                try:
                    return f.read(n)
                except MemoryError:
                    raise
                except Exception:
                    return b''  # damaged tail: pre-scan what is readable
            return _read

        with opener(input_path, 'rb') as f:
            for seg in _iter_line_segments(_read_or_stop(f), _SEG_BYTES):
                seg_text = seg.decode('utf-8', 'surrogateescape')
                additional_domains += DomainScrubber.extract_domains_from_text(seg_text)
                additional_usernames += UsernameScrubber.extract_usernames_from_text(seg_text)
                additional_hostnames += HostnameScrubber.extract_hostnames_from_text(
                    seg_text, syslog_counts=syslog_counts)
        additional_hostnames += HostnameScrubber.syslog_hosts_from_counts(syslog_counts)
    else:
        try:
            with open(input_path, 'rt', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except Exception as e:
            print(f"[!] Cannot read {input_path}: {e}")
            sys.exit(1)
        additional_domains += DomainScrubber.extract_domains_from_text(text)
        additional_usernames += UsernameScrubber.extract_usernames_from_text(text)
        additional_hostnames += HostnameScrubber.extract_hostnames_from_text(text)
        del text

    domain_dict, tld_map = extract_and_map_domains([], additional_domains, mappings)
    username_dict = extract_usernames([], additional_usernames, mappings)
    hostname_dict = extract_hostnames([], additional_hostnames, mappings)

    unpacked = getattr(args, 'unpacked', False)
    out_base = scrub_name(os.path.basename(input_path), hostname_dict, domain_dict=domain_dict)
    if drop_ext:
        out_base = strip_compression_ext(out_base)
    # A compressed output keeps its extension here even with --unpacked;
    # FileProcessor(decompress=True) converts it and drops the extension.
    output_path = os.path.join(os.path.dirname(input_path), scrubbed_output_name(out_base))

    # Serial numbers and SAP SIDs, exactly as the folder and archive chains
    # do: this entry point had silently dropped both, and a lone SAP log
    # scrubbed here kept its SID while the same file inside a bundle lost it.
    serial_dict = extract_serials([input_path], mappings)
    serial_scrubber = SerialScrubber(mappings=mappings)
    serial_scrubber.serial_dict = serial_dict
    sid_dict = extract_sids([input_path], mappings)
    sid_scrubber = SIDScrubber(mappings=mappings)
    sid_scrubber.sid_dict = sid_dict

    email_scrubber = EmailScrubber(mappings=mappings)
    username_scrubber = UsernameScrubber(username_dict)
    scrubbers = [
        ip_scrubber, ipv6_scrubber, mac_scrubber, keyword_scrubber,
        # Ahead of the email scrubber on purpose: in a URL the userinfo and
        # host together (user@host) match an email address exactly, so if
        # email ran first it would swallow both and the login would stop
        # being distinguishable from the host it authenticates against.
        AuthScrubber(mappings=mappings, email_scrubber=email_scrubber,
                     username_scrubber=username_scrubber),
        email_scrubber,
        HostnameScrubber(hostname_dict), DomainScrubber(domain_dict),
        LdapDnScrubber(mappings=mappings),
        username_scrubber,
        PasswordScrubber(mappings=mappings), CloudTokenScrubber(mappings=mappings),
        serial_scrubber, sid_scrubber,
    ]
    scrubbers = [s for s in scrubbers if s is not None]

    try:
        file_processor = FileProcessor(config, scrubbers, decompress=unpacked)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    # The scrub runs in place on a copy carrying the output name — the same
    # path archive mode's process_one_file takes — so compressed payloads go
    # through the streaming segment machinery instead of being read whole.
    in_place = os.path.abspath(output_path) == os.path.abspath(input_path)

    if in_place and comp and unpacked:
        # decompress=True would convert — and delete — the input file itself.
        print(f"[!] {os.path.basename(input_path)} already carries _scrubbed and "
              f"--unpacked would replace the input with its unpacked form — "
              f"rename the input or drop --unpacked")
        sys.exit(1)

    final_plain = strip_compression_ext(output_path)
    if comp and unpacked and final_plain != output_path and os.path.exists(final_plain):
        # File mode overwrites its output target; without this, process_file's
        # plain-sibling protection would keep the copy compressed instead.
        os.remove(final_plain)

    if not in_place:
        shutil.copyfile(input_path, output_path)
    ok = file_processor.process_file(output_path, logger, verbose_flag)
    if not ok:
        # Never leave input bytes under a _scrubbed name.
        if not in_place:
            try:
                os.remove(output_path)
            except OSError:
                pass
        print(f"[!] Scrubbing failed for {input_path} — no output written "
              f"(see messages above)")
        sys.exit(1)
    if not os.path.exists(output_path):
        # --unpacked converted the copy to plain, dropping the extension
        output_path = strip_compression_ext(output_path)

    print(f"[✓] Scrubbed file written to: {output_path}")

    ip_s = file_processor['ip']
    ipv6_s = file_processor['ipv6']

    dataset_dict = {s.name: dict(s.mapping) for s in file_processor.scrubbers}
    dataset_dict['subnet'] = ip_s.subnet_dict if ip_s else {}
    dataset_dict['state'] = ip_s.state if ip_s else {}
    dataset_dict['ipv6_subnet'] = ipv6_s.subnet_map if ipv6_s else {}
    dataset_dict['tld_map'] = tld_map

    saved_mapping_path = save_mappings(args, dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(dataset_dict, indent=4))

    counts = {s.name: len(s.mapping) for s in file_processor.scrubbers}
    subnet_count = len(dataset_dict.get('subnet', {}))
    ipv6_subnet_count = len(dataset_dict.get('ipv6_subnet', {}))
    total_obfuscations = sum(counts.values()) + subnet_count + ipv6_subnet_count

    print("\n------------------------------------------------------------")
    print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Usernames obfuscated      : {counts.get('user', 0)}")
    print(f"| IP addresses obfuscated   : {counts.get('ip', 0)}")
    print(f"| IPv4 subnets obfuscated   : {subnet_count}")
    print(f"| MAC addresses obfuscated  : {counts.get('mac', 0)}")
    print(f"| Domains obfuscated        : {counts.get('domain', 0)}")
    print(f"| Hostnames obfuscated      : {counts.get('hostname', 0)}")
    print(f"| IPv6 addresses obfuscated : {counts.get('ipv6', 0)}")
    print(f"| IPv6 subnets obfuscated   : {ipv6_subnet_count}")
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {counts.get('keyword', 0)}")
    if file_processor['email']:
        print(f"| Emails obfuscated         : {counts.get('email', 0)}")
    if file_processor['password']:
        print(f"| Passwords obfuscated      : {counts.get('password', 0)}")
    if file_processor['cloud_token']:
        print(f"| Cloud tokens obfuscated   : {counts.get('cloud_token', 0)}")
    print(f"| Total obfuscation entries : {total_obfuscations}")
    print(f"| Output file               : {output_path}")
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}")
        if getattr(args, '_enc_passphrase', None):
            print_enc_note(saved_mapping_path)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}")
    print(f"| Audit log                 : {audit_path}")
    print("------------------------------------------------------------\n")

    record = audit_record('file',
        inputs  = [{'path': os.path.abspath(input_path),  'sha256': sha256_file(input_path)}],
        outputs = [{'path': os.path.abspath(output_path), 'sha256': sha256_file(output_path)}],
        mapping_path = saved_mapping_path, args = args, version = SCRIPT_VERSION)
    write_audit_log(audit_path, record)
