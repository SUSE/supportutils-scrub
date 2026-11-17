import os
import json


def open_private(path, mode='w'):
    """Open for writing, created 0600 so the file is never readable by
    others, not even between create and chmod."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)   # an existing file keeps its old mode otherwise
    return os.fdopen(fd, mode, **({} if 'b' in mode else {'encoding': 'utf-8'}))


class Translator:

    @staticmethod
    def load_datasets_mappings(file_path):
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    @staticmethod
    def save_datasets(file_path, dataset_dict):
        with open_private(file_path) as f:
            json.dump(dataset_dict, f, indent=4)

    @staticmethod
    def save_datasets_encrypted(file_path, dataset_dict, passphrase: str) -> str:
        """Encrypt and save dataset. Returns the path of the encrypted file."""
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError(
                "Package 'cryptography' is required for --encrypt-mappings.\n"
                "Install with: pip install cryptography"
            )
        import base64
        import hashlib
        key = base64.urlsafe_b64encode(
            hashlib.scrypt(passphrase.encode('utf-8'), salt=b'supportutils-scrub-v1',
                           n=2**14, r=8, p=1, dklen=32)
        )
        token = Fernet(key).encrypt(json.dumps(dataset_dict).encode('utf-8'))
        enc_path = file_path + '.enc'
        with open_private(enc_path, 'wb') as f:
            f.write(token)
        return enc_path

