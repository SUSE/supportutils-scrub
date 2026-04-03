#!/usr/bin/env python3
import logging
import sys
import os
import re
import json
import argparse
import time
import pwd
import shutil
import subprocess
import hashlib
import socket
from datetime import datetime, timezone
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.ip_scrubber import IPScrubber
from supportutils_scrub.domain_scrubber import DomainScrubber
from supportutils_scrub.hostname_scrubber import HostnameScrubber
from supportutils_scrub.extractor import extract_supportconfig, create_txz, copy_folder_to_scrubbed, walk_supportconfig
from supportutils_scrub.translator import Translator
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger
from supportutils_scrub.keyword_scrubber import KeywordScrubber
from supportutils_scrub.username_scrubber import UsernameScrubber
from supportutils_scrub.mac_scrubber import MACScrubber
from supportutils_scrub.ipv6_scrubber import IPv6Scrubber
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.pcap_rewrite import rewrite_pcaps_with_tcprewrite
import shlex
from supportutils_scrub.serial_scrubber import SerialScrubber
from supportutils_scrub.verify import verify_scrubbed_folder

SCRIPT_VERSION = "1.4"
SCRIPT_DATE = "2026-04-01"

EXIT_OK           = 0   # success
EXIT_ERROR        = 1   # fatal error
EXIT_WARNING      = 2   # completed with warnings
EXIT_VERIFY_FAIL  = 3   # --verify found remaining sensitive data

def print_header(file=None):
    if file is None:
        file = sys.stdout
    print("\n"+"=" * 77, file=file)
    print("          Obfuscation Utility - supportutils-scrub", file=file)
    print("                      Version : {:<12}".format(SCRIPT_VERSION), file=file)
    print("                 Release Date : {:<12}".format(SCRIPT_DATE), file=file)
    print(file=file)
    print(" supportutils-scrub masks sensitive information from SUSE supportconfig", file=file)
    print(" tarballs, directories, plain files, and network captures. It replaces", file=file)
    print(" IPv4/IPv6 addresses, MAC addresses, domain names, hostnames, usernames,", file=file)
    print(" hardware serials, UUIDs, email addresses, passwords, and cloud tokens", file=file)
    print(" (AWS/Azure/GCE) consistently across all files in the archive.", file=file)
    print(" Mappings are saved to /var/tmp/obfuscation_HOSTNAME_TIMESTAMP_mappings.json", file=file)
    print(" (or .json.enc with --encrypt-mappings) and can be reused across runs", file=file)
    print(" with --mappings to keep values consistent across multiple archives.", file=file)
    print("=" * 77 + "\n", file=file)

def _warn_private_ip(config, file=None):
    if file is None:
        file = sys.stdout
    if config.get('obfuscate_private_ip', 'no').lower() != 'yes':
        print("[!] WARNING: Private IP obfuscation is DISABLED.", file=file)
        print( "    Only public IP addresses will be obfuscated.", file=file)
        print(f"    To also obfuscate private IPs (10.x, 172.16.x, 192.168.x),", file=file)
        print(f"    set 'obfuscate_private_ip = yes' in {DEFAULT_CONFIG_PATH}", file=file)
        print(file=file)

def print_footer(file=None):
    if file is None:
        file = sys.stdout
    print(" The obfuscated supportconfig has been successfully created. Please review", file=file)
    print(" its contents to ensure that all sensitive information has been properly", file=file)
    print(" obfuscated. Use --verify to perform a multi-layer post-scrub scan for", file=file)
    print(" remaining sensitive data. If some values were not obfuscated automatically,", file=file)
    print(" use --keywords or --keyword-file to add them manually.", file=file)
    print("=" * 77 + "\n", file=file)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Obfuscate SUSE supportconfig archives by masking sensitive data."
    )

    parser.add_argument("supportconfig_path", nargs="*", help="Path(s) to .txz/.tgz archive(s), a folder, a plain file, or '-' for stdin. Multiple archives are processed sequentially with shared mappings.")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH,
                        help="Path to config file (defaults provided)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--mappings", help="JSON or encrypted *.json.enc mapping file from a prior run. Prompts for passphrase when the file is encrypted.")
    parser.add_argument("--username", help="Additional usernames to obfuscate")
    parser.add_argument("--domain", help="Additional domains to obfuscate")
    parser.add_argument("--hostname", help="Additional hostnames to obfuscate")
    parser.add_argument("--keyword-file", help="File containing keywords to obfuscate")
    parser.add_argument("--keywords", help="Additional keywords to obfuscate")
    parser.add_argument("--rewrite-pcap", action="store_true",
               help="Rewrite one or more pcap files using mappings (IPv4/IPv6 subnet-aware).")
    parser.add_argument("--pcap-in", nargs="+", metavar="PCAP",
               help="Input pcap(s) to rewrite (requires --rewrite-pcap).")
    parser.add_argument("--pcap-out-dir", default=".", metavar="DIR",
               help="Directory for rewritten pcaps (default: current dir).")
    parser.add_argument("--print-tcprewrite", action="store_true",
               help="Print the exact tcprewrite commands executed.")
    parser.add_argument("--tcprewrite-path", default="tcprewrite",
               help="Path to tcprewrite binary (default: 'tcprewrite').")
    parser.add_argument("--secure-tmp", action="store_true",
        help="Extract archives to /dev/shm (tmpfs) to prevent sensitive data touching persistent storage.")
    parser.add_argument("--encrypt-mappings", action="store_true",
        help="Encrypt the mapping file with a passphrase (requires 'cryptography' package).")
    parser.add_argument("--no-mappings", action="store_true",
        help="Do not write a mapping file. Obfuscation cannot be reused across runs.")
    parser.add_argument("--decrypt-mappings", metavar="FILE",
        help="Decrypt and print an encrypted mapping file (*.json.enc) then exit.")
    parser.add_argument("--quiet", action="store_true",
        help="Suppress banner and per-file listing. Errors still go to stderr.")
    parser.add_argument("--output-dir", metavar="DIR",
        help="Directory for scrubbed output archives. Default: same directory as input.")
    parser.add_argument("--report", nargs='?', const=True, default=None, metavar="FILE",
        help="Write a JSON report. If FILE is given, write there; otherwise auto-generate a path alongside the mapping file.")
    parser.add_argument("--verify", action="store_true",
        help="After scrubbing, re-scan the output for remaining sensitive data. "
             "Checks: mapping values, IP/MAC allowlists, emails, secrets/keys, "
             "LDAP DNs, Kerberos principals, and (in folder mode) system identity "
             "from the original. Exit 3 if leaks found.")
    parser.add_argument("--stream", action="store_true",
        help="Streaming stdin mode: buffer the first 500 lines to build entity maps, "
             "then scrub and flush each subsequent line immediately. "
             "Use for live pipes such as: journalctl -f | supportutils-scrub --stream")

    return parser.parse_args()




def _next_fake_tld(counter: int) -> str:
    """Generate a fake TLD suffix: aaa, aab, ..., aaz, aba, abb, ..."""
    letters = 'abcdefghijklmnopqrstuvwxyz'
    a, b, c = counter // 676, (counter // 26) % 26, counter % 26
    return letters[a] + letters[b] + letters[c]


def _get_encryption_passphrase() -> str:
    import getpass
    passphrase = getpass.getpass("[*] Mapping file encryption passphrase: ")
    confirm    = getpass.getpass("[*] Confirm passphrase: ")
    if passphrase != confirm:
        print("[!] Passphrases do not match. Aborting.")
        sys.exit(1)
    if len(passphrase) < 8:
        print("[!] Passphrase must be at least 8 characters.")
        sys.exit(1)
    return passphrase


def _get_secure_tmp_base() -> str:
    """Return /dev/shm if available (tmpfs), else /var/tmp with a warning."""
    if os.path.exists('/dev/shm') and os.access('/dev/shm', os.W_OK):
        return '/dev/shm'
    print("[!] WARNING: /dev/shm not available, falling back to /var/tmp for temporary extraction.")
    return '/var/tmp'


def _print_enc_note(mapping_path, file=None):
    """Print a decryption hint after the mapping file line in a summary block."""
    if file is None:
        file = sys.stdout
    print("|   [encrypted] To decrypt:", file=file)
    print(f"|   supportutils-scrub --decrypt-mappings {mapping_path}", file=file)


def _load_mappings_file(path: str) -> dict:
    """Load a mapping file, plain JSON or AES-encrypted *.json.enc """
    if path.endswith('.json.enc'):
        import getpass
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("[!] Package 'cryptography' is required to load encrypted mappings.\n"
                  "    Install with: pip install cryptography")
            sys.exit(1)
        import base64 as _b64, hashlib as _hl
        passphrase = getpass.getpass(f"Passphrase for {path}: ").encode('utf-8')
        try:
            key = _b64.urlsafe_b64encode(
                _hl.scrypt(passphrase, salt=b'supportutils-scrub-v1',
                           n=16384, r=8, p=1, dklen=32)
            )
            with open(path, 'rb') as f:
                return json.loads(Fernet(key).decrypt(f.read()))
        except Exception:
            print(f"[!] Failed to decrypt {path}. Wrong passphrase or corrupted file.")
            sys.exit(1)
    else:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Failed to load mapping from {path}: {e}", file=sys.stderr)
            return {}


def _save_mappings(args, dataset_path, dataset_dict):
    """Save mapping file: plain, encrypted, or skip (--no-mappings)."""
    if args.no_mappings:
        print("[!] Mapping file not written (--no-mappings). Obfuscation cannot be reused.")
        return None
    if getattr(args, '_enc_passphrase', None):
        try:
            enc_path = Translator.save_datasets_encrypted(dataset_path, dataset_dict, args._enc_passphrase)
            print(f"[+] Encrypted mapping file : {enc_path}")
            return enc_path
        except RuntimeError as e:
            print(f"[!] Encryption failed: {e}")
            print("    Falling back to plain mapping file.")
    Translator.save_datasets(dataset_path, dataset_dict)
    return dataset_path


def _scrub_name(name: str, hostname_dict: dict) -> str:
    """Replace real hostnames in a filename/dirname """
    for real, fake in sorted(hostname_dict.items(), key=lambda x: len(x[0]), reverse=True):
        name = name.replace(real, fake)
    return name


def _dataset_paths(dataset_dir, timestamp, hostname_dict=None, input_name=None, report=False):
    """ Compute paths for mapping, audit, and (optionally) report files """
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


def _rename_extraction_paths(clean_folder_path: str, hostname_dict: dict, rename_top: bool = True) -> str:
    """ Rename any subdirectories inside clean_folder_path whose names contain a real hostname"""
    if not hostname_dict:
        return clean_folder_path
    for root, dirs, _ in os.walk(clean_folder_path, topdown=False):
        for d in dirs:
            scrubbed = _scrub_name(d, hostname_dict)
            if scrubbed != d:
                try:
                    os.rename(os.path.join(root, d), os.path.join(root, scrubbed))
                except Exception as e:
                    print(f"[!] Could not rename directory '{d}': {e}")
    if not rename_top:
        return clean_folder_path
    parent   = os.path.dirname(clean_folder_path)
    basename = os.path.basename(clean_folder_path)
    scrubbed_basename = _scrub_name(basename, hostname_dict)
    if scrubbed_basename != basename:
        new_path = os.path.join(parent, scrubbed_basename)
        try:
            if os.path.exists(new_path):
                shutil.rmtree(new_path)
            os.rename(clean_folder_path, new_path)
            return new_path
        except Exception as e:
            print(f"[!] Could not rename extraction folder: {e}")
    return clean_folder_path


def _sha256_file(path: str) -> str:
    """Return SHA-256 hex digest of a file, or 'unavailable' on error."""
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return 'unavailable'


def _write_audit_log(audit_path: str, record: dict):
    """Write an audit record as JSON (mode 0600)."""
    try:
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        with open(audit_path, 'w', encoding='utf-8') as f:
            json.dump(record, f, indent=4)
        os.chmod(audit_path, 0o600)
    except Exception as e:
        print(f"[!] Could not write audit log: {e}")


def _audit_record(mode: str, inputs: list, outputs: list, mapping_path, args) -> dict:
    """Build the audit record dict."""
    try:
        operator = pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        operator = os.environ.get('USER', os.environ.get('LOGNAME', 'unknown'))
    return {
        'tool':         'supportutils-scrub',
        'version':      SCRIPT_VERSION,
        'timestamp':    datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'operator':     operator,
        'hostname':     socket.gethostname(),
        'mode':         mode,
        'inputs':       inputs,
        'outputs':      outputs,
        'cli_args':     sys.argv[1:],
        'mapping_file': mapping_path or 'none (--no-mappings)',
    }


def build_hierarchical_domain_map(all_domains, existing_mappings):
    """ Builds a domain mapping dictionary that preserves parent-child relationship """
    valid_domains = {d for d in all_domains if '.' in d}

    sorted_domains = sorted(list(valid_domains), key=lambda d: len(d.split('.')))

    domain_dict = existing_mappings.get('domain', {})
    tld_map = existing_mappings.get('tld_map', {}) 
    base_domain_counter = len(domain_dict)
    sub_domain_counter = 0

    for domain in sorted_domains:
        if domain in domain_dict:
            continue

        parts = domain.split('.')
        parent_domain = '.'.join(parts[1:])

        if parent_domain in domain_dict:
            obfuscated_sub_part = f"sub_{sub_domain_counter}"
            sub_domain_counter += 1
            domain_dict[domain] = f"{obfuscated_sub_part}.{domain_dict[parent_domain]}"
        else:
            real_tld = parts[-1].lower()
            if real_tld not in tld_map:
                tld_map[real_tld] = _next_fake_tld(len(tld_map))
            fake_tld = tld_map[real_tld]
            domain_dict[domain] = f"domain_{base_domain_counter}.{fake_tld}"
            base_domain_counter += 1

    return domain_dict, tld_map


def extract_and_map_domains(report_files, additional_domains, mappings):
    """
    Extracts all unique domains from report files and builds the hierarchical map.
    """
    all_domains = set()

    for domain in additional_domains:
        DomainScrubber._add_domain_and_parents(domain, all_domains)

    files_to_scan = {
        'network.txt': ['# /etc/hosts', '# /etc/resolv.conf'],
        'nfs.txt': ['# /bin/egrep'],
        'ntp.txt': ['# /etc/ntp.conf', '# /etc/chrony.conf'],
        'sssd.txt': ['# /etc/sssd/sssd.conf'],
    }

    for file_path in report_files:
        basename = os.path.basename(file_path)
        if basename in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for section in files_to_scan[basename]:
                        domains_from_section = DomainScrubber.extract_domains_from_file_section(f, section)
                        all_domains.update(domains_from_section)
            except Exception as e:
                logging.error(f"Error reading file {file_path}: {e}")

    domain_map, tld_map = build_hierarchical_domain_map(all_domains, mappings)
    return domain_map, tld_map


def extract_hostnames(report_files, additional_hostnames, mappings):
    hostname_dict = mappings.get('hostname', {})
    hostname_counter = len(hostname_dict)
    all_hostnames = []

    for file in report_files:
        if 'network.txt' in file:
            hostnames_from_hosts = HostnameScrubber.extract_hostnames_from_hosts(file)
            hostnames_from_hostname = HostnameScrubber.extract_hostnames_from_hostname_section(file)
            all_hostnames.extend(hostnames_from_hosts)
            all_hostnames.extend(hostnames_from_hostname)

    all_hostnames.extend(additional_hostnames)

    for hostname in all_hostnames:
        if hostname not in hostname_dict:
            obfuscated_hostname = f"hostname_{hostname_counter}"
            hostname_dict[hostname] = obfuscated_hostname
            hostname_counter += 1

    return hostname_dict

def extract_usernames(report_files, additional_usernames, mappings):
    username_dict = mappings.get('user', {})
    username_counter = len(username_dict)
    all_usernames = []

    for file in report_files:
        if 'pam.txt' in file:
            section_starts = ['# /usr/bin/getent passwd', '# /etc/passwd']
            usernames = UsernameScrubber.extract_usernames_from_section(file, section_starts)
            all_usernames.extend(usernames)
        elif 'messages.txt' in file:
            usernames = UsernameScrubber.extract_usernames_from_messages(file)
            all_usernames.extend(usernames)
        elif 'security-apparmor.txt' in file:
            usernames = UsernameScrubber.extract_usernames_from_messages(file)
            all_usernames.extend(usernames)
        elif 'sssd.txt' in file:
            usernames = UsernameScrubber.extract_usernames_from_messages(file)
            all_usernames.extend(usernames)

    all_usernames.extend(additional_usernames)

    for username in all_usernames:
        if username not in username_dict:
            obfuscated_username = f"user_{username_counter}"
            username_dict[username] = obfuscated_username
            username_counter += 1

    return username_dict


def extract_serials(report_files, mappings):
    """Pre-scan targeted files for hardware serial numbers and system UUIDs."""
    serial_scrubber = SerialScrubber(mappings=mappings)
    target_files = {'basic-environment.txt', 'boot.txt', 'hardware.txt'}
    for fpath in report_files:
        if os.path.basename(fpath) in target_files:
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    serial_scrubber.pre_scan(f.read())
            except Exception:
                pass
    return serial_scrubber.serial_dict


def _write_report(report_path: str, archives: list, version: str,
                   verify_findings=None):
    """Write a JSON report showing which files contained each data category."""
    import socket as _sock
    data = {
        'tool':      'supportutils-scrub',
        'version':   version,
        'timestamp': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'hostname':  _sock.gethostname(),
        'archives':  archives,
    }
    if verify_findings:
        data['verify'] = {
            'total_findings': len(verify_findings),
            'findings': verify_findings,
        }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.chmod(report_path, 0o600)
        print(f"[✓] Coverage report written to:  {report_path}")
    except Exception as e:
        print(f"[!] Could not write report to {report_path}: {e}", file=sys.stderr)


def _init_scrubbers(args, config, logger):
    """ Shared scrubber initialisation used by folder mode and stdin mode """
    mappings = {}
    mapping_keywords = []
    if args.mappings:
        mappings = _load_mappings_file(args.mappings)
        mapping_keywords = list(mappings.get('keyword', {}).keys())

    cmd_keywords = []
    if args.keywords:
        cmd_keywords = [kw.strip() for kw in re.split(r'[,\s;]+', args.keywords.strip()) if kw.strip()]
    combined_keywords = set(cmd_keywords).union(mapping_keywords)

    try:
        keyword_scrubber = KeywordScrubber(keyword_file=args.keyword_file, cmd_keywords=list(combined_keywords))
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


def _is_supportconfig_folder(file_list):
    """Detect whether a folder looks like a supportconfig collection."""
    basenames = {os.path.basename(f) for f in file_list}
    return 'basic-environment.txt' in basenames


def run_folder_mode(args, logger):
    """ Process a directory: copy to {dir}_scrubbed/, scrub files in-place."""
    verbose_flag = args.verbose

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    quiet = getattr(args, 'quiet', False)
    err = sys.stderr  

    config = getattr(args, '_preloaded_config', None)
    if config is None:
        config = ConfigReader(DEFAULT_CONFIG_PATH).read_config(args.config)
    dataset_dir = config.get('dataset_dir', '/var/tmp')

    if quiet:
        print(f"supportutils-scrub v{SCRIPT_VERSION} — scrubbing IPs, hostnames, domains, "
              f"usernames, MACs, IPv6, serials", file=err)
        _warn_private_ip(config, file=err)
    else:
        _warn_private_ip(config)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        _init_scrubbers(args, config, logger)
    if not quiet and args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if not quiet and keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    try:
        report_files, scrubbed_path = copy_folder_to_scrubbed(args.supportconfig_path[0])
        if not quiet:
            print(f"[✓] Folder copied to: {scrubbed_path}")
    except Exception as e:
        print(f"[!] Error copying folder: {e}")
        raise

    # When Ctrl+C removes the partial _scrubbed folder rather than leaving half-scrubbed folder available.
    import signal
    def _cleanup_on_signal(signum, frame):
        try:
            sys.stderr.write(f"\n[!] Interrupted — removing partial output {scrubbed_path}\n")
            sys.stderr.flush()
            if os.path.exists(scrubbed_path):
                shutil.rmtree(scrubbed_path, ignore_errors=True)
        except Exception:
            pass
        os._exit(1)
    signal.signal(signal.SIGINT,  _cleanup_on_signal)
    signal.signal(signal.SIGTERM, _cleanup_on_signal)

    is_sc = _is_supportconfig_folder(report_files)

    scan_files = report_files if is_sc else []

    additional_domains = []
    if args.domain:
        additional_domains = re.split(r'[,\s;]+', args.domain)
    domain_dict, tld_map = extract_and_map_domains(scan_files, additional_domains, mappings)
    domain_scrubber = DomainScrubber(domain_dict)

    additional_usernames = []
    if args.username:
        additional_usernames = re.split(r'[,\s;]+', args.username)
    username_dict = extract_usernames(scan_files, additional_usernames, mappings)
    username_scrubber = UsernameScrubber(username_dict)

    additional_hostnames = []
    if args.hostname:
        additional_hostnames = re.split(r'[,\s;]+', args.hostname)
    hostname_dict = extract_hostnames(scan_files, additional_hostnames, mappings)
    hostname_scrubber = HostnameScrubber(hostname_dict)

    want_report = getattr(args, 'report', None) is not None
    input_basename = os.path.basename(args.supportconfig_path[0].rstrip('/'))
    dataset_path, audit_path, report_path = _dataset_paths(
        dataset_dir, timestamp, hostname_dict, input_name=input_basename, report=want_report)
    if want_report and isinstance(args.report, str):
        report_path = args.report  # user gave an explicit path

    serial_scrubber = None
    if is_sc:
        scrubbed_path = _rename_extraction_paths(scrubbed_path, hostname_dict)
        report_files = walk_supportconfig(scrubbed_path)
        serial_dict = extract_serials(report_files, mappings)
        serial_scrubber = SerialScrubber(mappings=mappings)
        serial_scrubber.serial_dict = serial_dict

    email_scrubber = EmailScrubber(mappings=mappings)

    try:
        file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, username_scrubber,
                                       hostname_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber,
                                       serial_scrubber=serial_scrubber, email_scrubber=email_scrubber,
                                       password_scrubber=PasswordScrubber(mappings=mappings),
                                       cloud_token_scrubber=CloudTokenScrubber(mappings=mappings))
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    total_ip_dict = {}
    total_domain_dict = {}
    total_user_dict = {}
    total_hostname_dict = {}
    total_keyword_dict = {}
    total_mac_dict = {}
    total_ipv6_dict = {}
    total_ipv4_subnet_dict = {}
    total_ipv6_subnet_dict = {}
    total_state = {}
    total_serial_dict = {}
    total_email_dict = {}
    total_password_dict = {}
    total_cloud_token_dict = {}

    if quiet:
        file_names = [os.path.basename(f) for f in report_files
                      if not re.match(r"^sa\d{8}(\.xz)?$", os.path.basename(f))]
        print("Scrubbing: " + " ".join(file_names), file=err)
    else:
        logger.info("Scrubbing:")
    _devnull = open(os.devnull, 'w') if quiet else None
    try:
        for report_file in report_files:
            basename = os.path.basename(report_file)
            if not quiet and not re.match(r"^sa\d{8}(\.xz)?$", basename):
                print(f"        {basename}")
            if quiet:
                _saved_stdout = sys.stdout
                sys.stdout = _devnull
            try:
                ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict_file = \
                    file_processor.process_file(report_file, logger, verbose_flag)
            finally:
                if quiet:
                    sys.stdout = _saved_stdout

            total_ip_dict.update(ip_dict)
            total_domain_dict.update(domain_dict)
            total_user_dict.update(username_dict)
            total_hostname_dict.update(hostname_dict)
            total_keyword_dict.update(keyword_dict)
            total_mac_dict.update(mac_dict)
            total_ipv6_dict.update(ipv6_dict)
            total_serial_dict.update(serial_dict_file)
            if file_processor.email_scrubber:
                total_email_dict.update(file_processor.email_scrubber.email_dict)
            if file_processor.password_scrubber:
                total_password_dict.update(file_processor.password_scrubber.password_dict)
            if file_processor.cloud_token_scrubber:
                total_cloud_token_dict.update(file_processor.cloud_token_scrubber.token_dict)
            if hasattr(file_processor, '_ipv4_subnet_map'):
                total_ipv4_subnet_dict = file_processor._ipv4_subnet_map
            if hasattr(file_processor, '_ipv4_state'):
                total_state = file_processor._ipv4_state
            if hasattr(file_processor, '_ipv6_subnet_map'):
                total_ipv6_subnet_dict.update(file_processor._ipv6_subnet_map)
    finally:
        if _devnull is not None:
            _devnull.close()

    dataset_dict = {
        'ip': total_ip_dict,
        'domain': total_domain_dict,
        'user': total_user_dict,
        'hostname': total_hostname_dict,
        'mac': total_mac_dict,
        'ipv6': total_ipv6_dict,
        'keyword': total_keyword_dict,
        'subnet': total_ipv4_subnet_dict,
        'state': total_state,
        'ipv6_subnet': total_ipv6_subnet_dict,
        'tld_map': tld_map,
        'serial': total_serial_dict,
        'email': total_email_dict,
        'password': total_password_dict,
        'cloud_token': total_cloud_token_dict,
    }

    saved_mapping_path = _save_mappings(args, dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(dataset_dict, indent=4))

    total_files_scrubbed = len(report_files)
    total_obfuscations = (
        len(total_user_dict) + len(total_ip_dict) + len(total_mac_dict)
        + len(total_domain_dict) + len(total_hostname_dict) + len(total_ipv6_dict)
        + len(total_keyword_dict) + len(total_ipv4_subnet_dict) + len(total_ipv6_subnet_dict)
        + len(total_serial_dict) + len(total_email_dict) + len(total_password_dict)
        + len(total_cloud_token_dict)
    )

    # for --quiet summary goes to stderr, only the output path goes to stdout for supportconfig -j.
    out = sys.stderr if quiet else sys.stdout

    print("\n------------------------------------------------------------", file=out)
    print(" Obfuscation Summary", file=out)
    print("------------------------------------------------------------", file=out)
    print(f"| Files obfuscated          : {total_files_scrubbed}", file=out)
    print(f"| Usernames obfuscated      : {len(total_user_dict)}", file=out)
    print(f"| IP addresses obfuscated   : {len(total_ip_dict)}", file=out)
    print(f"| IPv4 subnets obfuscated   : {len(total_ipv4_subnet_dict)}", file=out)
    print(f"| MAC addresses obfuscated  : {len(total_mac_dict)}", file=out)
    print(f"| Domains obfuscated        : {len(total_domain_dict)}", file=out)
    print(f"| Hostnames obfuscated      : {len(total_hostname_dict)}", file=out)
    print(f"| IPv6 addresses obfuscated : {len(total_ipv6_dict)}", file=out)
    print(f"| IPv6 subnets obfuscated   : {len(total_ipv6_subnet_dict)}", file=out)
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(total_keyword_dict)}", file=out)
    print(f"| Serials/UUIDs obfuscated  : {len(total_serial_dict)}", file=out)
    print(f"| Emails obfuscated         : {len(total_email_dict)}", file=out)
    print(f"| Passwords obfuscated      : {len(total_password_dict)}", file=out)
    print(f"| Cloud tokens obfuscated   : {len(total_cloud_token_dict)}", file=out)
    print(f"| Total obfuscation entries : {total_obfuscations}", file=out)
    if not quiet:
        print(f"| Output folder             : {scrubbed_path}", file=out)
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}", file=out)
        if getattr(args, '_enc_passphrase', None):
            _print_enc_note(saved_mapping_path)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}", file=out)
    print(f"| Audit log                 : {audit_path}", file=out)
    print("------------------------------------------------------------\n", file=out)

    verify_findings = []
    if getattr(args, 'verify', False):
        original_path = args.supportconfig_path[0]
        combined_mappings_for_verify = {
            'ip': total_ip_dict, 'ipv6': total_ipv6_dict, 'mac': total_mac_dict,
            'domain': total_domain_dict, 'hostname': total_hostname_dict,
            'user': total_user_dict, 'keyword': total_keyword_dict,
            'serial': total_serial_dict,
        }
        verify_findings = verify_scrubbed_folder(
            scrubbed_path, combined_mappings_for_verify,
            original_folder=original_path, config=config,
            check_allowlist=True, check_patterns=True,
            check_identity=True)
        vout = out  
        if verify_findings:
            print(f"[!] VERIFY: {len(verify_findings)} potential leak(s) found in scrubbed output:", file=vout)
            for f in verify_findings[:20]:
                print(f"    {f['file']}:{f['line']}  [{f['category']}]  {f['value']!r}", file=vout)
            if len(verify_findings) > 20:
                print(f"    ... and {len(verify_findings)-20} more (see --report for full details)", file=vout)
        else:
            print("[✓] VERIFY: No sensitive data found in scrubbed output.", file=vout)

    if quiet:
        print(scrubbed_path)

    if report_path:
        folder_report = [{'input': os.path.abspath(args.supportconfig_path[0]),
                          'output': os.path.abspath(scrubbed_path),
                          'files_total': len(report_files)}]
        _write_report(report_path, folder_report, SCRIPT_VERSION,
                      verify_findings=verify_findings)

    record = _audit_record('folder',
        inputs  = [{'path': os.path.abspath(args.supportconfig_path[0]), 'sha256': 'n/a (directory)'}],
        outputs = [{'path': os.path.abspath(scrubbed_path), 'sha256': 'n/a (directory)'}],
        mapping_path = saved_mapping_path, args = args)
    _write_audit_log(audit_path, record)

    if verify_findings:
        sys.exit(EXIT_VERIFY_FAIL)


def run_stdin_mode(args, logger):
    """ Reads from stdin, write scrubbed text to stdout """
    verbose_flag = args.verbose
    err = sys.stderr

    print_header(file=err)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(args.config)
    dataset_dir = config.get('dataset_dir', '/var/tmp')
    dataset_path, audit_path, _ = _dataset_paths(dataset_dir, timestamp)
    _warn_private_ip(config, file=err)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        _init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ", file=err)
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)", file=err)

    _STREAM_BOOTSTRAP      = 500  # max lines to collect during bootstrap
    _STREAM_BOOTSTRAP_SECS = 3.0  # max seconds to wait for bootstrap lines

    if getattr(args, 'stream', False):
        import select
        print(f"[i] Stream mode: collecting bootstrap (up to {_STREAM_BOOTSTRAP} lines "
              f"or {_STREAM_BOOTSTRAP_SECS:.0f}s)...", file=err)
        bootstrap_lines = []
        deadline = time.time() + _STREAM_BOOTSTRAP_SECS
        while len(bootstrap_lines) < _STREAM_BOOTSTRAP:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            ready, _, _ = select.select([sys.stdin], [], [], remaining)
            if not ready:
                break
            line = sys.stdin.readline()
            if not line:   # EOF
                break
            bootstrap_lines.append(line)
        bootstrap_text = ''.join(bootstrap_lines)

        additional_domains   = list(re.split(r'[,\s;]+', args.domain)    if args.domain    else [])
        additional_domains   += DomainScrubber.extract_domains_from_text(bootstrap_text)
        additional_usernames = list(re.split(r'[,\s;]+', args.username)  if args.username  else [])
        additional_usernames += UsernameScrubber.extract_usernames_from_text(bootstrap_text)
        additional_hostnames = list(re.split(r'[,\s;]+', args.hostname)  if args.hostname  else [])
        additional_hostnames += HostnameScrubber.extract_hostnames_from_text(bootstrap_text)

        domain_dict, tld_map  = extract_and_map_domains([], additional_domains,   mappings)
        username_dict         = extract_usernames([],       additional_usernames,  mappings)
        hostname_dict         = extract_hostnames([],       additional_hostnames,  mappings)

        try:
            file_processor = FileProcessor(config, ip_scrubber,
                                           DomainScrubber(domain_dict),
                                           UsernameScrubber(username_dict),
                                           HostnameScrubber(hostname_dict),
                                           mac_scrubber, ipv6_scrubber, keyword_scrubber,
                                           email_scrubber=EmailScrubber(mappings=mappings),
                                           password_scrubber=PasswordScrubber(mappings=mappings),
                                       cloud_token_scrubber=CloudTokenScrubber(mappings=mappings))
        except Exception as e:
            logger.error(f"Error initializing FileProcessor: {e}")
            sys.exit(1)

        scrubbed_bootstrap, ip_dict, domain_dict, username_dict, hostname_dict, \
            keyword_dict, mac_dict, ipv6_dict, serial_dict = \
            file_processor.process_text(bootstrap_text, logger, verbose_flag)
        sys.stdout.write(scrubbed_bootstrap)
        sys.stdout.flush()

        while True:
            line = sys.stdin.readline()
            if not line:   # EOF
                break
            scrubbed_line, _ip, _dom, _usr, _host, _kw, _mac, _ipv6, _ser = \
                file_processor.process_text(line, logger, False)
            sys.stdout.write(scrubbed_line)
            sys.stdout.flush()
            ip_dict.update(_ip);  mac_dict.update(_mac);  ipv6_dict.update(_ipv6)
            keyword_dict.update(_kw);  serial_dict.update(_ser)

    else:
        # Batch mode: read all stdin, then scrub ---
        text = sys.stdin.read()

        additional_domains   = list(re.split(r'[,\s;]+', args.domain)   if args.domain   else [])
        additional_domains   += DomainScrubber.extract_domains_from_text(text)
        additional_usernames = list(re.split(r'[,\s;]+', args.username) if args.username else [])
        additional_usernames += UsernameScrubber.extract_usernames_from_text(text)
        additional_hostnames = list(re.split(r'[,\s;]+', args.hostname) if args.hostname else [])
        additional_hostnames += HostnameScrubber.extract_hostnames_from_text(text)

        domain_dict, tld_map  = extract_and_map_domains([], additional_domains,   mappings)
        username_dict         = extract_usernames([],       additional_usernames,  mappings)
        hostname_dict         = extract_hostnames([],       additional_hostnames,  mappings)

        try:
            file_processor = FileProcessor(config, ip_scrubber,
                                           DomainScrubber(domain_dict),
                                           UsernameScrubber(username_dict),
                                           HostnameScrubber(hostname_dict),
                                           mac_scrubber, ipv6_scrubber, keyword_scrubber,
                                           email_scrubber=EmailScrubber(mappings=mappings),
                                           password_scrubber=PasswordScrubber(mappings=mappings),
                                       cloud_token_scrubber=CloudTokenScrubber(mappings=mappings))
        except Exception as e:
            logger.error(f"Error initializing FileProcessor: {e}")
            sys.exit(1)

        scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, \
            keyword_dict, mac_dict, ipv6_dict, serial_dict = \
            file_processor.process_text(text, logger, verbose_flag)
        sys.stdout.write(scrubbed_text)

    ipv4_subnet_dict = file_processor._ipv4_subnet_map if hasattr(file_processor, '_ipv4_subnet_map') else {}
    ipv6_subnet_dict = file_processor._ipv6_subnet_map if hasattr(file_processor, '_ipv6_subnet_map') else {}
    state = file_processor._ipv4_state if hasattr(file_processor, '_ipv4_state') else {}

    dataset_dict = {
        'ip': ip_dict,
        'domain': domain_dict,
        'user': username_dict,
        'hostname': hostname_dict,
        'mac': mac_dict,
        'ipv6': ipv6_dict,
        'keyword': keyword_dict,
        'subnet': ipv4_subnet_dict,
        'state': state,
        'ipv6_subnet': ipv6_subnet_dict,
        'tld_map': tld_map,
        'serial': {},
    }

    saved_mapping_path = _save_mappings(args, dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---", file=err)
        print(json.dumps(dataset_dict, indent=4), file=err)

    total_obfuscations = (
        len(username_dict) + len(ip_dict) + len(mac_dict)
        + len(domain_dict) + len(hostname_dict) + len(ipv6_dict)
        + len(keyword_dict) + len(ipv4_subnet_dict) + len(ipv6_subnet_dict)
    )

    print("\n------------------------------------------------------------", file=err)
    print(" Obfuscation Summary", file=err)
    print("------------------------------------------------------------", file=err)
    print(f"| Usernames obfuscated      : {len(username_dict)}", file=err)
    print(f"| IP addresses obfuscated   : {len(ip_dict)}", file=err)
    print(f"| IPv4 subnets obfuscated   : {len(ipv4_subnet_dict)}", file=err)
    print(f"| MAC addresses obfuscated  : {len(mac_dict)}", file=err)
    print(f"| Domains obfuscated        : {len(domain_dict)}", file=err)
    print(f"| Hostnames obfuscated      : {len(hostname_dict)}", file=err)
    print(f"| IPv6 addresses obfuscated : {len(ipv6_dict)}", file=err)
    print(f"| IPv6 subnets obfuscated   : {len(ipv6_subnet_dict)}", file=err)
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(keyword_dict)}", file=err)
    if file_processor.email_scrubber:
        print(f"| Emails obfuscated         : {len(file_processor.email_scrubber.email_dict)}", file=err)
    if file_processor.password_scrubber:
        print(f"| Passwords obfuscated      : {len(file_processor.password_scrubber.password_dict)}", file=err)
    if file_processor.cloud_token_scrubber:
        print(f"| Cloud tokens obfuscated   : {len(file_processor.cloud_token_scrubber.token_dict)}", file=err)
    print(f"| Total obfuscation entries : {total_obfuscations}", file=err)
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}", file=err)
        if getattr(args, '_enc_passphrase', None):
            _print_enc_note(saved_mapping_path, file=err)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}", file=err)
    print(f"| Audit log                 : {audit_path}", file=err)
    print("------------------------------------------------------------\n", file=err)

    record = _audit_record('stdin',
        inputs  = [{'path': 'stdin', 'sha256': 'n/a'}],
        outputs = [{'path': 'stdout', 'sha256': 'n/a'}],
        mapping_path = saved_mapping_path, args = args)
    _write_audit_log(audit_path, record)

    print_footer(file=err)


def run_file_mode(args, logger):
    """
    Process a single plain file: write scrubbed copy to {path}_scrubbed, summary to stdout.
    """
    verbose_flag = args.verbose
    input_path = args.supportconfig_path[0]
    output_path = input_path + '_scrubbed'

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    config_reader_f = ConfigReader(DEFAULT_CONFIG_PATH)
    config_f = config_reader_f.read_config(args.config)
    dataset_dir = config_f.get('dataset_dir', '/var/tmp')
    dataset_path, audit_path, _ = _dataset_paths(dataset_dir, timestamp)

    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(args.config)
    _warn_private_ip(config)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        _init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)")

    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except Exception as e:
        print(f"[!] Cannot read {input_path}: {e}")
        sys.exit(1)

    additional_domains = list(re.split(r'[,\s;]+', args.domain) if args.domain else [])
    additional_domains += DomainScrubber.extract_domains_from_text(text)

    additional_usernames = list(re.split(r'[,\s;]+', args.username) if args.username else [])
    additional_usernames += UsernameScrubber.extract_usernames_from_text(text)

    additional_hostnames = list(re.split(r'[,\s;]+', args.hostname) if args.hostname else [])
    additional_hostnames += HostnameScrubber.extract_hostnames_from_text(text)

    domain_dict, tld_map = extract_and_map_domains([], additional_domains, mappings)
    domain_scrubber = DomainScrubber(domain_dict)
    username_dict = extract_usernames([], additional_usernames, mappings)
    username_scrubber = UsernameScrubber(username_dict)
    hostname_dict = extract_hostnames([], additional_hostnames, mappings)
    hostname_scrubber = HostnameScrubber(hostname_dict)

    email_scrubber = EmailScrubber(mappings=mappings)

    try:
        file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, username_scrubber,
                                       hostname_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber,
                                       email_scrubber=email_scrubber,
                                       password_scrubber=PasswordScrubber(mappings=mappings),
                                       cloud_token_scrubber=CloudTokenScrubber(mappings=mappings))
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)

    scrubbed_text, ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict = \
        file_processor.process_text(text, logger, verbose_flag)

    if scrubbed_text != text:
        header = (
            "#" + "-" * 93 + "\n"
            "# INFO: Sensitive information in this file has been obfuscated by supportutils-scrub.\n"
            "#" + "-" * 93 + "\n\n"
        )
        final_content = header + scrubbed_text
    else:
        final_content = scrubbed_text

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(final_content)
    except Exception as e:
        print(f"[!] Cannot write {output_path}: {e}")
        sys.exit(1)

    print(f"[✓] Scrubbed file written to: {output_path}")

    ipv4_subnet_dict = file_processor._ipv4_subnet_map if hasattr(file_processor, '_ipv4_subnet_map') else {}
    ipv6_subnet_dict = file_processor._ipv6_subnet_map if hasattr(file_processor, '_ipv6_subnet_map') else {}
    state = file_processor._ipv4_state if hasattr(file_processor, '_ipv4_state') else {}

    dataset_dict = {
        'ip': ip_dict,
        'domain': domain_dict,
        'user': username_dict,
        'hostname': hostname_dict,
        'mac': mac_dict,
        'ipv6': ipv6_dict,
        'keyword': keyword_dict,
        'subnet': ipv4_subnet_dict,
        'state': state,
        'ipv6_subnet': ipv6_subnet_dict,
        'tld_map': tld_map,
        'serial': {},
    }

    saved_mapping_path = _save_mappings(args, dataset_path, dataset_dict)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(dataset_dict, indent=4))

    total_obfuscations = (
        len(username_dict) + len(ip_dict) + len(mac_dict)
        + len(domain_dict) + len(hostname_dict) + len(ipv6_dict)
        + len(keyword_dict) + len(ipv4_subnet_dict) + len(ipv6_subnet_dict)
    )

    print("\n------------------------------------------------------------")
    print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Usernames obfuscated      : {len(username_dict)}")
    print(f"| IP addresses obfuscated   : {len(ip_dict)}")
    print(f"| IPv4 subnets obfuscated   : {len(ipv4_subnet_dict)}")
    print(f"| MAC addresses obfuscated  : {len(mac_dict)}")
    print(f"| Domains obfuscated        : {len(domain_dict)}")
    print(f"| Hostnames obfuscated      : {len(hostname_dict)}")
    print(f"| IPv6 addresses obfuscated : {len(ipv6_dict)}")
    print(f"| IPv6 subnets obfuscated   : {len(ipv6_subnet_dict)}")
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(keyword_dict)}")
    if file_processor.email_scrubber:
        print(f"| Emails obfuscated         : {len(file_processor.email_scrubber.email_dict)}")
    if file_processor.password_scrubber:
        print(f"| Passwords obfuscated      : {len(file_processor.password_scrubber.password_dict)}")
    if file_processor.cloud_token_scrubber:
        print(f"| Cloud tokens obfuscated   : {len(file_processor.cloud_token_scrubber.token_dict)}")
    print(f"| Total obfuscation entries : {total_obfuscations}")
    print(f"| Output file               : {output_path}")
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}")
        if getattr(args, '_enc_passphrase', None):
            _print_enc_note(saved_mapping_path)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}")
    print(f"| Audit log                 : {audit_path}")
    print("------------------------------------------------------------\n")

    record = _audit_record('file',
        inputs  = [{'path': os.path.abspath(input_path),  'sha256': _sha256_file(input_path)}],
        outputs = [{'path': os.path.abspath(output_path), 'sha256': _sha256_file(output_path)}],
        mapping_path = saved_mapping_path, args = args)
    _write_audit_log(audit_path, record)


def _process_one_archive(archive_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag):
    """ Process a single .txz/.tgz archive using current_mappings for consistency."""
    try:
        ip_scrubber = IPScrubber(config, mappings=current_mappings)
        mac_scrubber = MACScrubber(config, mappings=current_mappings)
        ipv6_scrubber = IPv6Scrubber(config, mappings=current_mappings)
    except Exception as e:
        logger.error(f"Error initializing scrubbers for {archive_path}: {e}")
        raise

    extract_base = _get_secure_tmp_base() if getattr(args, 'secure_tmp', False) else None

    new_txz_file_path = None
    clean_folder_path = None
    verify_findings = []
    report_file_hits = {}
    total_serial_dict = {}
    tld_map = {}
    report_files = []


    import signal as _sig
    _prev_sigint  = _sig.getsignal(_sig.SIGINT)
    _prev_sigterm = _sig.getsignal(_sig.SIGTERM)
    def _archive_cleanup_on_signal(signum, frame):
        try:
            sys.stderr.write(f"\n[!] Interrupted — cleaning up {clean_folder_path}\n")
            sys.stderr.flush()
            if clean_folder_path and os.path.exists(clean_folder_path):
                shutil.rmtree(clean_folder_path, ignore_errors=True)
        except Exception:
            pass
        os._exit(1)
    _sig.signal(_sig.SIGINT,  _archive_cleanup_on_signal)
    _sig.signal(_sig.SIGTERM, _archive_cleanup_on_signal)

    try:
        try:
            report_files, clean_folder_path = extract_supportconfig(archive_path, logger, extract_base=extract_base)
        except Exception as e:
            print(f"[!] Error during extraction of {archive_path}: {e}")
            raise

        additional_domains = []
        if args.domain:
            additional_domains = re.split(r'[,\s;]+', args.domain)
        domain_dict, tld_map = extract_and_map_domains(report_files, additional_domains, current_mappings)
        domain_scrubber = DomainScrubber(domain_dict)

        additional_usernames = []
        if args.username:
            additional_usernames = re.split(r'[,\s;]+', args.username)
        username_dict = extract_usernames(report_files, additional_usernames, current_mappings)
        username_scrubber = UsernameScrubber(username_dict)

        additional_hostnames = []
        if args.hostname:
            additional_hostnames = re.split(r'[,\s;]+', args.hostname)
        hostname_dict = extract_hostnames(report_files, additional_hostnames, current_mappings)
        hostname_scrubber = HostnameScrubber(hostname_dict)

        clean_folder_path = _rename_extraction_paths(clean_folder_path, hostname_dict)
        report_files = walk_supportconfig(clean_folder_path)

        serial_dict = extract_serials(report_files, current_mappings)
        serial_scrubber = SerialScrubber(mappings=current_mappings)
        serial_scrubber.serial_dict = serial_dict

        archive_dir = os.path.dirname(os.path.abspath(archive_path))
        archive_basename = os.path.basename(archive_path)
        if archive_path.endswith(".tar.gz"):
            archive_name_no_ext = archive_basename[:-7]
        else:
            archive_name_no_ext = os.path.splitext(archive_basename)[0]
        scrubbed_archive_name = _scrub_name(archive_name_no_ext, hostname_dict)
        out_dir = getattr(args, 'output_dir', None) or archive_dir
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        new_txz_file_path = os.path.join(out_dir, scrubbed_archive_name + "_scrubbed.txz")

        email_scrubber = EmailScrubber(mappings=current_mappings)
        password_scrubber = PasswordScrubber(mappings=current_mappings)
        cloud_token_scrubber = CloudTokenScrubber(mappings=current_mappings)

        try:
            file_processor = FileProcessor(config, ip_scrubber, domain_scrubber, username_scrubber,
                                           hostname_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber,
                                           serial_scrubber=serial_scrubber, email_scrubber=email_scrubber,
                                           password_scrubber=password_scrubber,
                                           cloud_token_scrubber=cloud_token_scrubber)
        except Exception as e:
            logger.error(f"Error initializing FileProcessor: {e}")
            raise

        total_ip_dict = {}
        total_domain_dict = {}
        total_user_dict = {}
        total_hostname_dict = {}
        total_keyword_dict = {}
        total_mac_dict = {}
        total_ipv6_dict = {}
        total_ipv4_subnet_dict = {}
        total_ipv6_subnet_dict = {}
        total_state = {}

        logger.info("Scrubbing:")
        for report_file in report_files:
            basename = os.path.basename(report_file)
            if not re.match(r"^sa\d{8}(\.xz)?$", basename):
                if not getattr(args, 'quiet', False):
                    print(f"        {basename}")

            ip_dict, domain_dict, username_dict, hostname_dict, keyword_dict, mac_dict, ipv6_dict, serial_dict_file = \
                file_processor.process_file(report_file, logger, verbose_flag)

            total_ip_dict.update(ip_dict)
            total_domain_dict.update(domain_dict)
            total_user_dict.update(username_dict)
            total_hostname_dict.update(hostname_dict)
            total_keyword_dict.update(keyword_dict)
            total_mac_dict.update(mac_dict)
            total_ipv6_dict.update(ipv6_dict)
            total_serial_dict.update(serial_dict_file)
            if hasattr(file_processor, '_ipv4_subnet_map'):
                total_ipv4_subnet_dict = file_processor._ipv4_subnet_map
            if hasattr(file_processor, '_ipv4_state'):
                total_state = file_processor._ipv4_state
            if hasattr(file_processor, '_ipv6_subnet_map'):
                total_ipv6_subnet_dict.update(file_processor._ipv6_subnet_map)

            file_hits = []
            if ip_dict:           file_hits.append('ip')
            if ipv6_dict:         file_hits.append('ipv6')
            if mac_dict:          file_hits.append('mac')
            if domain_dict:       file_hits.append('domain')
            if hostname_dict:     file_hits.append('hostname')
            if username_dict:     file_hits.append('username')
            if keyword_dict:      file_hits.append('keyword')
            if serial_dict_file:  file_hits.append('serial')
            if file_hits:
                report_file_hits[os.path.basename(report_file)] = file_hits

        create_txz(clean_folder_path, new_txz_file_path)
        print(f"[✓] Scrubbed archive written to: {new_txz_file_path}")

        verify_findings = []
        if getattr(args, 'verify', False):
            combined_mappings_for_verify = {
                'ip': total_ip_dict, 'ipv6': total_ipv6_dict, 'mac': total_mac_dict,
                'domain': total_domain_dict, 'hostname': total_hostname_dict,
                'user': total_user_dict, 'keyword': total_keyword_dict,
                'serial': total_serial_dict,
            }
            verify_findings = verify_scrubbed_folder(
                clean_folder_path, combined_mappings_for_verify,
                config=config,
                check_allowlist=True, check_patterns=True,
                check_identity=False)
            if verify_findings:
                print(f"[!] VERIFY: {len(verify_findings)} potential leak(s) found in scrubbed output:")
                for f in verify_findings[:20]:
                    print(f"    {f['file']}:{f['line']}  [{f['category']}]  {f['value']!r}")
                if len(verify_findings) > 20:
                    print(f"    ... and {len(verify_findings)-20} more (see --report for full details)")
            else:
                print("[✓] VERIFY: No sensitive data found in scrubbed output.")

    finally:
        _sig.signal(_sig.SIGINT,  _prev_sigint)
        _sig.signal(_sig.SIGTERM, _prev_sigterm)
        if clean_folder_path and os.path.exists(clean_folder_path):
            try:
                shutil.rmtree(clean_folder_path)
            except Exception as e:
                print(f"[!] Could not remove temp folder {clean_folder_path}: {e}")

    try:
        stat = os.stat(new_txz_file_path)
        archive_size_mb = stat.st_size / (1024 * 1024)
        archive_owner = pwd.getpwuid(stat.st_uid).pw_name
    except Exception:
        archive_size_mb = 0
        archive_owner = "unknown"

    updated_mappings = {
        'ip': total_ip_dict,
        'domain': total_domain_dict,
        'user': total_user_dict,
        'hostname': total_hostname_dict,
        'mac': total_mac_dict,
        'ipv6': total_ipv6_dict,
        'keyword': total_keyword_dict,
        'subnet': total_ipv4_subnet_dict,
        'state': total_state,
        'ipv6_subnet': total_ipv6_subnet_dict,
        'tld_map': tld_map,
        'serial': total_serial_dict,
        'email': email_scrubber.email_dict,
        'password': password_scrubber.password_dict,
        'cloud_token': cloud_token_scrubber.token_dict,
    }

    stats = {
        'archive_path': archive_path,
        'output_path': new_txz_file_path,
        'files': len(report_files),
        'size_mb': archive_size_mb,
        'owner': archive_owner,
        'report_data': {
            'input':  archive_path,
            'output': new_txz_file_path,
            'files_total': len(report_files),
            'file_hits': report_file_hits,
        },
        'verify_findings': verify_findings,
    }

    return updated_mappings, stats


def main():
    env_opts = os.environ.get('SUPPORTUTILS_SCRUB_OPTS', '')
    if env_opts:
        try:
            sys.argv[1:1] = shlex.split(env_opts)
        except ValueError:
            print('[!] Warning: could not parse SUPPORTUTILS_SCRUB_OPTS', file=sys.stderr)

    args = parse_args()

    if not args.decrypt_mappings and len(args.supportconfig_path) == 1 \
            and args.supportconfig_path[0].endswith('.json.enc'):
        args.decrypt_mappings = args.supportconfig_path[0]

    #decrypt and print an encrypted mapping file
    if args.decrypt_mappings:
        import getpass
        enc_file = args.decrypt_mappings
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("[!] Package 'cryptography' is required. Install with: pip install cryptography")
            sys.exit(1)
        import base64, hashlib
        passphrase = getpass.getpass(f"Passphrase for {enc_file}: ").encode('utf-8')
        try:
            key = base64.urlsafe_b64encode(
                hashlib.scrypt(passphrase, salt=b'supportutils-scrub-v1',
                               n=16384, r=8, p=1, dklen=32)
            )
            with open(enc_file, 'rb') as f:
                data = json.loads(Fernet(key).decrypt(f.read()))
            print(json.dumps(data, indent=2))
        except Exception:
            print("[!] Decryption failed. Wrong passphrase or corrupted file.")
            sys.exit(1)
        return

    verbose_flag = args.verbose
    logger = SupportutilsScrubLogger(log_level="verbose" if verbose_flag else "normal")

    _early_config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    _early_config = _early_config_reader.read_config(args.config)
    args.secure_tmp       = args.secure_tmp       or _early_config.get('secure_tmp',       'no').lower() == 'yes'
    args.encrypt_mappings = args.encrypt_mappings or _early_config.get('encrypt_mappings', 'no').lower() == 'yes'
    args._preloaded_config = _early_config  
    if args.encrypt_mappings and args.no_mappings:
        print("[!] --encrypt-mappings and --no-mappings are mutually exclusive.")
        sys.exit(1)

    if args.encrypt_mappings and not args.no_mappings:
        try:
            args._enc_passphrase = _get_encryption_passphrase()
        except RuntimeError as e:
            print(f"[!] {e}")
            sys.exit(1)
    else:
        args._enc_passphrase = None

    paths = args.supportconfig_path  

    is_stdin = (len(paths) == 0 and not sys.stdin.isatty()) \
               or (len(paths) == 1 and paths[0] == '-')
    is_folder = len(paths) == 1 and os.path.isdir(paths[0])
    is_file = (len(paths) == 1
               and os.path.isfile(paths[0])
               and not paths[0].endswith(('.txz', '.tgz', '.tar.gz')))

    if is_stdin:
        run_stdin_mode(args, logger)
        return

    if is_file:
        if not getattr(args, 'quiet', False):
            print_header()
        run_file_mode(args, logger)
        print_footer()
        return

    if is_folder:
        if not getattr(args, 'quiet', False):
            print_header()
        run_folder_mode(args, logger)
        if not getattr(args, 'quiet', False):
            print_footer()
        return

    if not getattr(args, 'quiet', False):
        print_header()

    if args.rewrite_pcap and not paths:
        if not args.mappings or not args.pcap_in:
            print("[!] For --rewrite-pcap without a supportconfig, provide --mappings and --pcap-in")
            sys.exit(2)
        mappings = _load_mappings_file(args.mappings)
        rewrite_pcaps_with_tcprewrite(
            mappings, args.pcap_in, args.pcap_out_dir,
            tcprewrite=args.tcprewrite_path,
            print_cmd=args.print_tcprewrite,
            logger=logger,
        )
        print_footer()
        return

    if not paths:
        print("[!] No input specified. Provide a .txz/.tgz archive, folder, plain file, or '-' for stdin.")
        sys.exit(2)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    config_reader = ConfigReader(DEFAULT_CONFIG_PATH)
    config = config_reader.read_config(args.config)
    dataset_dir = config.get('dataset_dir', '/var/tmp')
    _warn_private_ip(config, file=sys.stderr if getattr(args, 'quiet', False) else None)

    if args.rewrite_pcap:
        if not args.pcap_in:
            print("[!] --rewrite-pcap needs --pcap-in PCAP(s)")
            sys.exit(2)
        if not args.mappings:
            print("[!] --rewrite-pcap requires --mappings to provide subnet data")
            sys.exit(2)
        mapping_src_path = args.mappings
        try:
            mappings_for_pcap = _load_mappings_file(mapping_src_path)
        except SystemExit:
            raise
        except Exception as e:
            print(f"[!] Failed to read mappings for pcap rewrite from {mapping_src_path}: {e}")
            sys.exit(2)
        rewrite_pcaps_with_tcprewrite(
            mappings_for_pcap, args.pcap_in, args.pcap_out_dir,
            tcprewrite=args.tcprewrite_path,
            print_cmd=args.print_tcprewrite,
            logger=logger,
        )

    initial_mappings = {}
    mapping_keywords = []
    if args.mappings:
        initial_mappings = _load_mappings_file(args.mappings)
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ")
        mapping_keywords = list(initial_mappings.get('keyword', {}).keys())

    cmd_keywords = []
    if args.keywords:
        cmd_keywords = [kw.strip() for kw in re.split(r'[,\s;]+', args.keywords.strip()) if kw.strip()]
    combined_keywords = set(cmd_keywords).union(mapping_keywords)
    try:
        keyword_scrubber = KeywordScrubber(keyword_file=args.keyword_file, cmd_keywords=list(combined_keywords))
        if not keyword_scrubber.is_loaded():
            if args.keywords or args.keyword_file:
                print("[!] Keyword obfuscation disabled (no keywords loaded)")
            keyword_scrubber = None
    except Exception as e:
        logger.error(f"Failed to initialize KeywordScrubber: {e}")
        keyword_scrubber = None

    current_mappings = initial_mappings
    all_stats = []

    failed_archives = []
    for i, archive_path in enumerate(paths):
        if len(paths) > 1:
            print(f"\n[{i+1}/{len(paths)}] Processing: {os.path.basename(archive_path)}")
        try:
            current_mappings, stats = _process_one_archive(
                archive_path, current_mappings, args, config, keyword_scrubber, logger, verbose_flag
            )
            all_stats.append(stats)
        except Exception as e:
            print(f"[!] Failed to process {archive_path}: {e}", file=sys.stderr)
            failed_archives.append(archive_path)
            if len(paths) == 1:
                sys.exit(EXIT_ERROR)

    all_verify_findings = []
    for s in all_stats:
        all_verify_findings.extend(s.get('verify_findings', []))

    if all_verify_findings:
        verify_exit = EXIT_VERIFY_FAIL
    else:
        verify_exit = EXIT_OK

    hostname_dict_final = current_mappings.get('hostname', {})
    want_report = getattr(args, 'report', None) is not None
    input_basename = os.path.basename(paths[0].rstrip('/')) if paths else ''
    dataset_path, audit_path, report_path = _dataset_paths(
        dataset_dir, timestamp, hostname_dict_final, input_name=input_basename, report=want_report)
    if want_report and isinstance(args.report, str):
        report_path = args.report  

    if report_path:
        archives_report = [s['report_data'] for s in all_stats]
        _write_report(report_path, archives_report, SCRIPT_VERSION,
                      verify_findings=all_verify_findings)

    saved_mapping_path = _save_mappings(args, dataset_path, current_mappings)
    if saved_mapping_path:
        print(f"[✓] Mapping file saved to:       {saved_mapping_path}")

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---")
        print(json.dumps(current_mappings, indent=4))

    total_files_scrubbed = sum(s['files'] for s in all_stats)
    total_obfuscations = (
        len(current_mappings.get('user', {}))
        + len(current_mappings.get('ip', {}))
        + len(current_mappings.get('mac', {}))
        + len(current_mappings.get('domain', {}))
        + len(current_mappings.get('hostname', {}))
        + len(current_mappings.get('ipv6', {}))
        + len(current_mappings.get('keyword', {}))
        + len(current_mappings.get('subnet', {}))
        + len(current_mappings.get('ipv6_subnet', {}))
        + len(current_mappings.get('serial', {}))
        + len(current_mappings.get('email', {}))
        + len(current_mappings.get('password', {}))
        + len(current_mappings.get('cloud_token', {}))
    )

    print("\n------------------------------------------------------------")
    if len(paths) > 1:
        print(f" Combined Obfuscation Summary ({len(paths)} archives)")
    else:
        print(" Obfuscation Summary")
    print("------------------------------------------------------------")
    print(f"| Files obfuscated          : {total_files_scrubbed}")
    print(f"| Usernames obfuscated      : {len(current_mappings.get('user', {}))}")
    print(f"| IP addresses obfuscated   : {len(current_mappings.get('ip', {}))}")
    print(f"| IPv4 subnets obfuscated   : {len(current_mappings.get('subnet', {}))}")
    print(f"| MAC addresses obfuscated  : {len(current_mappings.get('mac', {}))}")
    print(f"| Domains obfuscated        : {len(current_mappings.get('domain', {}))}")
    print(f"| Hostnames obfuscated      : {len(current_mappings.get('hostname', {}))}")
    print(f"| IPv6 addresses obfuscated : {len(current_mappings.get('ipv6', {}))}")
    print(f"| IPv6 subnets obfuscated   : {len(current_mappings.get('ipv6_subnet', {}))}")
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {len(current_mappings.get('keyword', {}))}")
    print(f"| Serials/UUIDs obfuscated  : {len(current_mappings.get('serial', {}))}")
    print(f"| Emails obfuscated         : {len(current_mappings.get('email', {}))}")
    print(f"| Passwords obfuscated      : {len(current_mappings.get('password', {}))}")
    print(f"| Cloud tokens obfuscated   : {len(current_mappings.get('cloud_token', {}))}")
    print(f"| Total obfuscation entries : {total_obfuscations}")
    if len(all_stats) == 1:
        stats = all_stats[0]
        print(f"| Size                      : {stats['size_mb']:.2f} MB")
        print(f"| Owner                     : {stats['owner']}")
    for stats in all_stats:
        print(f"| Output archive            : {stats['output_path']}")
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}")
        if getattr(args, '_enc_passphrase', None):
            _print_enc_note(saved_mapping_path)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}")
    print(f"| Audit log                 : {audit_path}")
    if failed_archives:
        print(f"| FAILED archives           : {len(failed_archives)}")
        for fa in failed_archives:
            print(f"|   - {fa}")
    print("------------------------------------------------------------\n")

    record = _audit_record('archive',
        inputs  = [{'path': os.path.abspath(p), 'sha256': _sha256_file(p)} for p in paths],
        outputs = [{'path': s['output_path'], 'sha256': _sha256_file(s['output_path'])} for s in all_stats],
        mapping_path = saved_mapping_path, args = args)
    _write_audit_log(audit_path, record)

    print_footer()

    if failed_archives:
        sys.exit(EXIT_ERROR)
    if verify_exit == EXIT_VERIFY_FAIL:
        sys.exit(EXIT_VERIFY_FAIL)

if __name__ == "__main__":
    main()
