# scrubber/translator.py

import json

class Translator:
    @staticmethod
    def save_translation(file_path, translation_dict):
        """
        Save translation dictionary to a JSON file.
        """
        with open(file_path, 'w') as json_file:
            json.dump(translation_dict, json_file)

