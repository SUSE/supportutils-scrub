# keyword_scrubber.py

import random
import string
import logging

class KeywordScrubber:
    def __init__(self, keyword_file):
        self.keyword_file = keyword_file
        self.keyword_dict = {}

    def load_keywords(self):
        logging.info("Loaded keyword file: %s", self.keyword_file)
        with open(self.keyword_file, 'r') as file:
            for line in file:
                keyword = line.strip()
                if keyword:
                    self.keyword_dict[keyword] = self._generate_obfuscated_keyword()
        logging.info("Loaded keywords: %s", self.keyword_dict)

        
    def _generate_obfuscated_keyword(self):
        # Generate a random length between 7 and 10
        random_length = random.randint(7, 10)
        return 'x' * random_length

    def scrub(self, text):
        obfuscated_dict = {}
        for keyword, obfuscated in self.keyword_dict.items():
            if keyword in text:
                text = text.replace(keyword, obfuscated)
                obfuscated_dict[keyword] = obfuscated
        return text, obfuscated_dict
    
    def is_loaded(self):
        """ Check if keywords are loaded """
        return bool(self.keyword_dict)    