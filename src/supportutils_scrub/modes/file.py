import os
import sys
import json
import shutil
from datetime import datetime

from supportutils_scrub.main import SCRIPT_VERSION
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.processor import (
    FileProcessor, single_file_compression, scrubbed_output_name,
    strip_compression_ext, compression_magic_ok, looks_binary, is_binary_head,
    _iter_line_segments, _SEG_BYTES, _TEXT_PROBE,
)
from supportutils_scrub.pipeline import (
    save_mappings_or_exit,
    warn_private_ip, init_scrubbers, scrub_name,
    extract_and_map_domains, extract_hostnames, extract_usernames,
    dataset_paths, extract_serials, extract_sids,
    split_names, chain_seed, build_chain, chain_mappings, is_pcap,
)
from supportutils_scrub.audit import (
    print_enc_note, sha256_file, audit_record, write_audit_log,
)


class ScrubRefused(Exception):
    """The file was not scrubbed and no output was left behind."""


def scrub_loose_file(input_path, mappings, args, config, keyword_scrubber,
                     logger, verbose_flag):
    """Scrub one loose file to <name>_scrubbed<ext>, next to it or in
    --output-dir. File mode and a loose file in a multi-input run both come
    here, so both learn names from the text and take --hostname/--domain/
    --username alike.

    Returns (output_path, mappings, file_processor); raises ScrubRefused."""
    name = os.path.basename(input_path)
    comp = single_file_compression(name)
    drop_ext = False

    # Cheap streaming checks before anything is read whole or copied: a
    # payload that is not text is refused up front; a name that lies about
    # the content is scrubbed as the plain text it really is and the
    # misleading extension is dropped from the output name.
    if comp:
        ext, opener = comp
        if not compression_magic_ok(input_path, ext):
            if looks_binary(input_path):
                raise ScrubRefused(f"{name}: neither a {ext[1:]} stream nor text "
                                   f"— nothing to scrub")
            print(f"[!] {name}: not a {ext[1:]} stream despite "
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
            if is_binary_head(head):
                raise ScrubRefused(f"{name}: {ext[1:]} payload is not text "
                                   f"— nothing to scrub")
    elif is_pcap(input_path):
        raise ScrubRefused(f"{name}: packet capture — pass it next to the "
                           f"supportconfig it belongs to, or use --rewrite-pcap "
                           f"--mappings FILE --pcap-in {name}")
    elif looks_binary(input_path):
        # process_file would leave it as is, and the copy would ship byte
        # for byte under a _scrubbed name
        raise ScrubRefused(f"{name}: binary content, not text — nothing to scrub")

    additional_domains = split_names(args.domain)
    additional_usernames = split_names(args.username)
    additional_hostnames = split_names(args.hostname)

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
            raise ScrubRefused(f"Cannot read {input_path}: {e}")
        additional_domains += DomainScrubber.extract_domains_from_text(text)
        additional_usernames += UsernameScrubber.extract_usernames_from_text(text)
        additional_hostnames += HostnameScrubber.extract_hostnames_from_text(text)
        del text

    domain_dict, tld_map = extract_and_map_domains([], additional_domains, mappings)
    username_dict = extract_usernames([], additional_usernames, mappings)
    hostname_dict = extract_hostnames([], additional_hostnames, mappings,
                                      config=config)

    unpacked = getattr(args, 'unpacked', False)
    out_base = scrub_name(name, hostname_dict, domain_dict=domain_dict, config=config)
    if drop_ext:
        out_base = strip_compression_ext(out_base)
    out_dir = getattr(args, 'output_dir', None) or os.path.dirname(os.path.abspath(input_path))
    os.makedirs(out_dir, exist_ok=True)
    # A compressed output keeps its extension here even with --unpacked;
    # FileProcessor(decompress=True) converts it and drops the extension.
    output_path = os.path.join(out_dir, scrubbed_output_name(out_base))

    # Serial numbers and SAP SIDs, exactly as the folder and archive chains
    # do: a lone SAP log must lose its SID like it would inside a bundle.
    serial_dict = extract_serials([input_path], mappings, config=config)
    sid_dict = extract_sids([input_path], mappings)
    seed = chain_seed(mappings, hostname_dict, domain_dict, username_dict,
                      serial_dict, sid_dict, keyword_scrubber)
    file_processor = FileProcessor(config, build_chain(seed, config), decompress=unpacked)

    # The scrub runs in place on a copy carrying the output name, so
    # compressed payloads go through the streaming segment machinery instead
    # of being read whole.
    in_place = os.path.abspath(output_path) == os.path.abspath(input_path)

    if in_place and comp and unpacked:
        # decompress=True would convert — and delete — the input file itself.
        raise ScrubRefused(f"{name} already carries _scrubbed and --unpacked would "
                           f"replace the input with its unpacked form — rename "
                           f"the input or drop --unpacked")

    final_plain = strip_compression_ext(output_path)
    if comp and unpacked and final_plain != output_path and os.path.exists(final_plain):
        # The output target is overwritten; without this, process_file's
        # plain-sibling protection would keep the copy compressed instead.
        os.remove(final_plain)

    if not in_place:
        shutil.copyfile(input_path, output_path)
    logger.info(f"Scrubbing file: {os.path.basename(output_path)}")
    if not file_processor.process_file(output_path, logger, verbose_flag):
        # Never leave input bytes under a _scrubbed name.
        if not in_place:
            try:
                os.remove(output_path)
            except OSError:
                pass
        raise ScrubRefused(f"Scrubbing failed for {input_path} — no output "
                           f"written (see messages above)")
    if not os.path.exists(output_path):
        # --unpacked converted the copy to plain, dropping the extension
        output_path = strip_compression_ext(output_path)

    return output_path, chain_mappings(file_processor.scrubbers, mappings, tld_map), file_processor


def run_file_mode(args, logger):
    verbose_flag = args.verbose
    input_path = args.supportconfig_path[0]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    config = args._preloaded_config
    dataset_path, audit_path, _ = dataset_paths(config.dataset_dir, timestamp)
    warn_private_ip(config)

    mappings, keyword_scrubber, _ip, _mac, _ipv6 = init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    try:
        output_path, dataset_dict, file_processor = scrub_loose_file(
            input_path, mappings, args, config, keyword_scrubber, logger, verbose_flag)
    except ScrubRefused as e:
        print(f"[!] {e}")
        sys.exit(1)

    print(f"[✓] Scrubbed file written to: {output_path}")

    saved_mapping_path = save_mappings_or_exit(args, dataset_path, dataset_dict)

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
