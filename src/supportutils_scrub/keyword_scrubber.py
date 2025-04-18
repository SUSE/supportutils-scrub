import random
import logging
import re
import os

class KeywordScrubber:
    def __init__(self, keyword_file=None, cmd_keywords=None):
        self.keyword_file = keyword_file
        self.cmd_keywords = cmd_keywords or []
        self.keyword_dict = {}
        self.load_keywords()

    def load_keywords(self):
        # Load from file
        if self.keyword_file:
            if not os.path.isfile(self.keyword_file):
                print(f"[!] Keyword file not found: {self.keyword_file}")
            else:
                try:
                    with open(self.keyword_file, 'r', encoding='utf-8') as f:
                        print(f"[✓] Loading keywords from file: {self.keyword_file}")
                        for line in f:
                            # Strip comments and whitespace
                            kw = line.split('#', 1)[0].strip().lower()
                            if not kw:
                                continue
                            if kw not in self.keyword_dict:
                                self.keyword_dict[kw] = self._generate_obfuscated_keyword()

                except Exception as e:
                    print(f"[!] Error reading keyword file: {e}")
        # Load from command line arguments
        if self.cmd_keywords:
            for keyword in self.cmd_keywords:
                if keyword.lower() not in self.keyword_dict:
                    logging.info("[✓] Loading keywords from command line arguments")
                    self.keyword_dict[keyword.lower()] = self._generate_obfuscated_keyword()

    def _generate_obfuscated_keyword(self):
        random_length = random.randint(7, 10)
        return 'x' * random_length

    def scrub(self, text):
        obfuscated_dict = {}
        for keyword, obfuscated in self.keyword_dict.items():
            # Use regex for case-insensitive replacement
            text, count = re.subn(re.escape(keyword), obfuscated, text, flags=re.IGNORECASE)
            if count > 0:
                obfuscated_dict[keyword] = obfuscated
        return text, obfuscated_dict

    def is_loaded(self):
        return bool(self.keyword_dict)
