# scrubber/translator.py

import json

class Translator:
    @staticmethod
    def save_translation(file_path, translation_dict):
        """
        Save translation dictionary to a JSON file.
        """
        with open(file_path, 'w') as json_file:
            json.dump(translation_dict, json_file, indent = 4)

    @staticmethod
    def load_datasets_mappings(file_path):

        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            # Handle the case where the mappings file doesn't exist.
            # This could involve returning an empty dictionary or raising an error.
            return {}
        

    @staticmethod
    def save_datasets(file_path, dataset_dict):
        """
        Save aggregated translation dictionaries to a JSON file.
        """
        with open(file_path, 'w') as json_file:
            json.dump(dataset_dict, json_file, indent=4)        