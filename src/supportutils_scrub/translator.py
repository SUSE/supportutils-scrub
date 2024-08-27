import os
import json
import logging

class Translator:
    @staticmethod
    def save_translation(file_path, translation_dict):
        # Ensure the directory exists before saving the file
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w') as json_file:
            json.dump(translation_dict, json_file, indent=4)

    @staticmethod
    def load_datasets_mappings(file_path):
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            # Handle the case where the mappings file doesn't exist.
            return {}

    @staticmethod
    def save_datasets(file_path, dataset_dict):
        # Ensure the directory exists before saving the file
        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
            except PermissionError as e:
                logging.error(f"Permission denied: Could not create directory {directory}. Please run with appropriate permissions.")
                return
            except Exception as e:
                logging.error(f"Failed to create directory {directory}: {e}")
                return

        try:
            with open(file_path, 'w') as json_file:
                json.dump(dataset_dict, json_file, indent=4)
        except Exception as e:
            logging.error(f"Failed to save datasets to {file_path}: {e}")
