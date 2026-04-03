# audit.py — mapping I/O, audit trail, reports

import os
import sys
import json
import hashlib
import pwd
import socket
from datetime import datetime, timezone
from supportutils_scrub.translator import Translator


def get_encryption_passphrase():
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


def get_secure_tmp_base():
    if os.path.exists('/dev/shm') and os.access('/dev/shm', os.W_OK):
        return '/dev/shm'
    print("[!] WARNING: /dev/shm not available, falling back to /var/tmp")
    return '/var/tmp'


def print_enc_note(mapping_path, file=None):
    out = file or sys.stdout
    print("|   [encrypted] To decrypt:", file=out)
    print(f"|   supportutils-scrub --decrypt-mappings {mapping_path}", file=out)


def load_mappings_file(path):
    if path.endswith('.json.enc'):
        import getpass
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("[!] Package 'cryptography' is required to load encrypted mappings.\n"
                  "    Install with: pip install cryptography")
            sys.exit(1)
        import base64, hashlib as _hl
        passphrase = getpass.getpass(f"Passphrase for {path}: ").encode('utf-8')
        try:
            key = base64.urlsafe_b64encode(
                _hl.scrypt(passphrase, salt=b'supportutils-scrub-v1',
                           n=16384, r=8, p=1, dklen=32))
            with open(path, 'rb') as f:
                return json.loads(Fernet(key).decrypt(f.read()))
        except Exception:
            print(f"[!] Failed to decrypt {path}. Wrong passphrase or corrupted file.")
            sys.exit(1)
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load mapping from {path}: {e}", file=sys.stderr)
        return {}


def save_mappings(args, dataset_path, dataset_dict):
    if args.no_mappings:
        print("[!] Mapping file not written (--no-mappings).")
        return None
    if getattr(args, '_enc_passphrase', None):
        try:
            return Translator.save_datasets_encrypted(
                dataset_path, dataset_dict, args._enc_passphrase)
        except Exception as e:
            print(f"[!] Encrypted mapping failed: {e}, falling back to plain.")
    Translator.save_datasets(dataset_path, dataset_dict)
    return dataset_path


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return 'unavailable'


def write_audit_log(audit_path, record):
    try:
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        with open(audit_path, 'w', encoding='utf-8') as f:
            json.dump(record, f, indent=4)
        os.chmod(audit_path, 0o600)
    except Exception as e:
        print(f"[!] Could not write audit log: {e}")


def audit_record(mode, inputs, outputs, mapping_path, args, version):
    try:
        operator = pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        operator = os.environ.get('USER', os.environ.get('LOGNAME', 'unknown'))
    return {
        'tool':         'supportutils-scrub',
        'version':      version,
        'timestamp':    datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'operator':     operator,
        'hostname':     socket.gethostname(),
        'mode':         mode,
        'inputs':       inputs,
        'outputs':      outputs,
        'cli_args':     sys.argv[1:],
        'mapping_file': mapping_path or 'none (--no-mappings)',
    }


def write_report(report_path, archives, version, verify_findings=None):
    data = {
        'tool':      'supportutils-scrub',
        'version':   version,
        'timestamp': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'hostname':  socket.gethostname(),
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
