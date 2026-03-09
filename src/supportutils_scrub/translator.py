import os
import json
import logging

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

        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(dataset_dict, f, indent=4)
            os.chmod(file_path, 0o600)
        except PermissionError:
            logging.error(f"Permission denied writing {file_path}. Run with appropriate privileges.")
        except Exception as e:
            logging.error(f"Failed to save datasets to {file_path}: {e}")

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
        os.makedirs(os.path.dirname(enc_path), exist_ok=True)
        with open(enc_path, 'wb') as f:
            f.write(token)
        os.chmod(enc_path, 0o600)
        return enc_path

