import sys
import os
import json
import argparse
import shlex

from supportutils_scrub.main import SCRIPT_VERSION, SCRIPT_DATE, EXIT_ERROR
from supportutils_scrub.config import DEFAULT_CONFIG_PATH
from supportutils_scrub.config_reader import ConfigReader
from supportutils_scrub.supportutils_scrub_logger import SupportutilsScrubLogger
from supportutils_scrub.audit import get_encryption_passphrase, load_mappings_file
from supportutils_scrub.pcap_rewrite import rewrite_pcaps_with_tcprewrite


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
    args.secure_tmp       = args.secure_tmp       or _early_config.secure_tmp
    args.encrypt_mappings = args.encrypt_mappings or _early_config.encrypt_mappings
    args._preloaded_config = _early_config
    if args.encrypt_mappings and args.no_mappings:
        print("[!] --encrypt-mappings and --no-mappings are mutually exclusive.")
        sys.exit(1)

    if args.encrypt_mappings and not args.no_mappings:
        try:
            args._enc_passphrase = get_encryption_passphrase()
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
        from supportutils_scrub.modes.stdin import run_stdin_mode
        print_header(file=sys.stderr)
        run_stdin_mode(args, logger)
        print_footer(file=sys.stderr)
        return

    if is_file:
        from supportutils_scrub.modes.file import run_file_mode
        if not getattr(args, 'quiet', False):
            print_header()
        run_file_mode(args, logger)
        print_footer()
        return

    if is_folder:
        from supportutils_scrub.modes.folder import run_folder_mode
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
        mappings = load_mappings_file(args.mappings)
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

    from supportutils_scrub.modes.archive import run_archive_mode
    run_archive_mode(paths, args, logger)

    print_footer()
