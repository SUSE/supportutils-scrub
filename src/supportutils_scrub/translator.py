# translator.py

import os
import json
import logging

class Translator:
    @staticmethod
    def save_translation(file_path, translation_dict):
        """
        Save translation dictionary to a JSON file.
        """
        # Ensure the directory exists before saving the file
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w') as json_file:
            json.dump(translation_dict, json_file, indent=4)

    @staticmethod
    def load_datasets_mappings(file_path):
        """
        Load dataset mappings from a JSON file.
        """
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            # Handle the case where the mappings file doesn't exist.
            # Return an empty dictionary
            return {}

    @staticmethod
    def save_datasets(file_path, dataset_dict):
        """
        Save aggregated translation dictionaries to a JSON file.
        """
        # Ensure the directory exists before saving the file
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        try:
            with open(file_path, 'w') as json_file:
                json.dump(dataset_dict, json_file, indent=4)
        except Exception as e:
            logging.error(f"Failed to save datasets to {file_path}: {e}")
