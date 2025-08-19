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

