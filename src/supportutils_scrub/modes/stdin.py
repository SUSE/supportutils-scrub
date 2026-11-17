import os
import sys
import re
import json
import time
from datetime import datetime

from supportutils_scrub.main import SCRIPT_VERSION, EXIT_ERROR
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
from supportutils_scrub.processor import FileProcessor
from supportutils_scrub.pipeline import (
    warn_private_ip, init_scrubbers,
    extract_and_map_domains, extract_hostnames, extract_usernames,
    dataset_paths,
)
from supportutils_scrub.audit import (
    save_mappings, print_enc_note, audit_record, write_audit_log,
)


def _build_processor(config, ip_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber,
                     domain_dict, username_dict, hostname_dict, mappings, logger,
                     serial_scrubber, sid_scrubber):
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
        HostnameScrubber(hostname_dict, config=config), DomainScrubber(domain_dict),
        LdapDnScrubber(mappings=mappings),
        username_scrubber,
        PasswordScrubber(mappings=mappings), CloudTokenScrubber(mappings=mappings),
        serial_scrubber, sid_scrubber,
    ]
    scrubbers = [s for s in scrubbers if s is not None]
    try:
        return FileProcessor(config, scrubbers)
    except Exception as e:
        logger.error(f"Error initializing FileProcessor: {e}")
        sys.exit(1)


_STREAM_BOOTSTRAP      = 500
_STREAM_BOOTSTRAP_SECS = 3.0


def _split_lines(buf):
    parts = buf.split(b'\n')
    return [p + b'\n' for p in parts[:-1]], parts[-1]


def _decode(lines):
    return b''.join(lines).decode('utf-8', 'surrogateescape')


def _emit(text):
    out = sys.stdout.buffer
    out.write(text.encode('utf-8', 'surrogateescape'))
    out.flush()


def _drop_stdout():
    # the reader went away (| head): send what is still buffered nowhere,
    # so interpreter shutdown does not fail flushing into the closed pipe
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


def _prepare(args, config, text, mappings, ip_scrubber, mac_scrubber,
             ipv6_scrubber, keyword_scrubber, logger):
    additional_domains   = list(re.split(r'[,\s;]+', args.domain)   if args.domain   else [])
    additional_domains   += DomainScrubber.extract_domains_from_text(text)
    additional_usernames = list(re.split(r'[,\s;]+', args.username) if args.username else [])
    additional_usernames += UsernameScrubber.extract_usernames_from_text(text)
    additional_hostnames = list(re.split(r'[,\s;]+', args.hostname) if args.hostname else [])
    additional_hostnames += HostnameScrubber.extract_hostnames_from_text(text)

    domain_dict, tld_map  = extract_and_map_domains([], additional_domains,   mappings)
    username_dict         = extract_usernames([],       additional_usernames,  mappings)
    hostname_dict         = extract_hostnames([],       additional_hostnames,  mappings,
                                              config=config)
    # stdin has no file name to pick the serial and SID sources by, so
    # learn from the buffered text itself
    serial_scrubber = SerialScrubber(mappings=mappings)
    serial_scrubber.pre_scan(text)
    sid_scrubber = SIDScrubber(mappings=mappings)
    sid_scrubber.pre_scan(text)

    file_processor = _build_processor(
        config, ip_scrubber, mac_scrubber, ipv6_scrubber, keyword_scrubber,
        domain_dict, username_dict, hostname_dict, mappings, logger,
        serial_scrubber, sid_scrubber)
    return file_processor, tld_map


def run_stdin_mode(args, logger):
    verbose_flag = args.verbose
    err = sys.stderr

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    config = args._preloaded_config
    dataset_dir = config.dataset_dir
    dataset_path, audit_path, _ = dataset_paths(dataset_dir, timestamp)
    warn_private_ip(config, file=err)

    mappings, keyword_scrubber, ip_scrubber, mac_scrubber, ipv6_scrubber = \
        init_scrubbers(args, config, logger)

    if args.mappings:
        print(f"[✓] Dataset mapping loaded from: {args.mappings} ", file=err)
    if keyword_scrubber is None and (args.keywords or args.keyword_file):
        print("[!] Keyword obfuscation disabled (no keywords loaded)", file=err)

    def prepare(text):
        return _prepare(args, config, text, mappings, ip_scrubber, mac_scrubber,
                        ipv6_scrubber, keyword_scrubber, logger)

    # Fakes already written to stdout can only be reversed with the mapping,
    # so it is saved however the input ends: EOF, Ctrl-C or a closed pipe.
    file_processor = None
    interrupted = False
    try:
        if getattr(args, 'stream', False):
            import select
            print(f"[i] Stream mode: collecting bootstrap (up to {_STREAM_BOOTSTRAP} lines "
                  f"or {_STREAM_BOOTSTRAP_SECS:.0f}s)...", file=err)
            # os.read on the fd, never sys.stdin: a buffered readline would
            # pull the whole burst into Python's buffer and select() on the
            # fd would then see nothing left to read
            fd = sys.stdin.fileno()
            bootstrap_lines, pending, eof = [], b'', False
            deadline = time.time() + _STREAM_BOOTSTRAP_SECS
            while len(bootstrap_lines) < _STREAM_BOOTSTRAP:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([fd], [], [], remaining)
                if not ready:
                    break
                chunk = os.read(fd, 65536)
                if not chunk:
                    eof = True
                    break
                lines, pending = _split_lines(pending + chunk)
                bootstrap_lines += lines
            if eof and pending:
                bootstrap_lines.append(pending)
                pending = b''
            bootstrap_text = _decode(bootstrap_lines)

            file_processor, tld_map = prepare(bootstrap_text)
            _emit(file_processor.process_text(bootstrap_text, logger, verbose_flag))

            while not eof:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                lines, pending = _split_lines(pending + chunk)
                if lines:
                    _emit(file_processor.process_text(_decode(lines), logger, False))
            if pending:
                _emit(file_processor.process_text(_decode([pending]), logger, False))

        else:
            text = sys.stdin.buffer.read().decode('utf-8', 'surrogateescape')
            file_processor, tld_map = prepare(text)
            _emit(file_processor.process_text(text, logger, verbose_flag))
    except KeyboardInterrupt:
        interrupted = True
    except BrokenPipeError:
        _drop_stdout()
    finally:
        if file_processor is not None:
            _finish(args, file_processor, tld_map, keyword_scrubber,
                    dataset_path, audit_path, verbose_flag)
    if interrupted:
        sys.exit(130)


def _finish(args, file_processor, tld_map, keyword_scrubber,
            dataset_path, audit_path, verbose_flag):
    err = sys.stderr
    ip_s = file_processor['ip']
    ipv6_s = file_processor['ipv6']

    dataset_dict = {s.name: dict(s.mapping) for s in file_processor.scrubbers}
    dataset_dict['subnet'] = ip_s.subnet_dict if ip_s else {}
    dataset_dict['state'] = {**(ip_s.state if ip_s else {}),
                             **(getattr(ipv6_s, 'state', None) or {})}
    dataset_dict['ipv6_subnet'] = ipv6_s.subnet_map if ipv6_s else {}
    dataset_dict['tld_map'] = tld_map
    from supportutils_scrub import det as _det
    if _det.current_key():
        dataset_dict[_det.KEY_FIELD] = _det.current_key()

    try:
        saved_mapping_path = save_mappings(args, dataset_path, dataset_dict)
    except Exception as e:
        print(f"[!] Mapping file not saved: {e}", file=err)
        sys.exit(EXIT_ERROR)

    if verbose_flag:
        print("\n--- Obfuscated Mapping Preview ---", file=err)
        print(json.dumps(dataset_dict, indent=4), file=err)

    counts = {s.name: len(s.mapping) for s in file_processor.scrubbers}
    subnet_count = len(dataset_dict.get('subnet', {}))
    ipv6_subnet_count = len(dataset_dict.get('ipv6_subnet', {}))
    total_obfuscations = sum(counts.values()) + subnet_count + ipv6_subnet_count

    print("\n------------------------------------------------------------", file=err)
    print(" Obfuscation Summary", file=err)
    print("------------------------------------------------------------", file=err)
    print(f"| Usernames obfuscated      : {counts.get('user', 0)}", file=err)
    print(f"| IP addresses obfuscated   : {counts.get('ip', 0)}", file=err)
    print(f"| IPv4 subnets obfuscated   : {subnet_count}", file=err)
    print(f"| MAC addresses obfuscated  : {counts.get('mac', 0)}", file=err)
    print(f"| Domains obfuscated        : {counts.get('domain', 0)}", file=err)
    print(f"| Hostnames obfuscated      : {counts.get('hostname', 0)}", file=err)
    print(f"| IPv6 addresses obfuscated : {counts.get('ipv6', 0)}", file=err)
    print(f"| IPv6 subnets obfuscated   : {ipv6_subnet_count}", file=err)
    if keyword_scrubber:
        print(f"| Keywords obfuscated       : {counts.get('keyword', 0)}", file=err)
    if file_processor['email']:
        print(f"| Emails obfuscated         : {counts.get('email', 0)}", file=err)
    if file_processor['password']:
        print(f"| Passwords obfuscated      : {counts.get('password', 0)}", file=err)
    if file_processor['cloud_token']:
        print(f"| Cloud tokens obfuscated   : {counts.get('cloud_token', 0)}", file=err)
    print(f"| Total obfuscation entries : {total_obfuscations}", file=err)
    if saved_mapping_path:
        print(f"| Mapping file              : {saved_mapping_path}", file=err)
        if getattr(args, '_enc_passphrase', None):
            print_enc_note(saved_mapping_path, file=err)
    if args.keyword_file and keyword_scrubber:
        print(f"| Keyword file              : {args.keyword_file}", file=err)
    print(f"| Audit log                 : {audit_path}", file=err)
    print("------------------------------------------------------------\n", file=err)

    record = audit_record('stdin',
        inputs  = [{'path': 'stdin', 'sha256': 'n/a'}],
        outputs = [{'path': 'stdout', 'sha256': 'n/a'}],
        mapping_path = saved_mapping_path, args = args, version = SCRIPT_VERSION)
    write_audit_log(audit_path, record)
