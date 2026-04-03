import random
import logging
import re
import os
from supportutils_scrub.scrubber import Scrubber

class KeywordScrubber(Scrubber):
    name = 'keyword'

    def __init__(self, keyword_file=None, cmd_keywords=None):
        self.keyword_file = keyword_file
        self.cmd_keywords = cmd_keywords or []
        self.keyword_dict = {}
        self.load_keywords()

    def load_keywords(self):
        if self.keyword_file:
            if not os.path.isfile(self.keyword_file):
                print(f"[!] Keyword file not found: {self.keyword_file}")
            else:
                try:
                    with open(self.keyword_file, 'r', encoding='utf-8') as f:
                        print(f"[✓] Loading keywords from file: {self.keyword_file}")
                        for line in f:
                            kw = line.split('#', 1)[0].strip().lower()
                            if not kw:
                                continue
                            if kw not in self.keyword_dict:
                                self.keyword_dict[kw] = self._generate_obfuscated_keyword()

                except Exception as e:
                    print(f"[!] Error reading keyword file: {e}")
        if self.cmd_keywords:
            for keyword in self.cmd_keywords:
                if keyword.lower() not in self.keyword_dict:
                    logging.info("[✓] Loading keywords from command line arguments")
                    self.keyword_dict[keyword.lower()] = self._generate_obfuscated_keyword()

    def _generate_obfuscated_keyword(self):
        random_length = random.randint(7, 10)
        return 'x' * random_length

    @property
    def mapping(self):
        return self.keyword_dict

    def scrub(self, text):
        for keyword, obfuscated in self.keyword_dict.items():
            text = re.sub(re.escape(keyword), obfuscated, text, flags=re.IGNORECASE)
        return text

    def is_loaded(self):
        return bool(self.keyword_dict)
