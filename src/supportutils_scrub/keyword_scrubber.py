import logging
import re
import os
import sys
from supportutils_scrub.scrubber import Scrubber


class KeywordScrubber(Scrubber):
    name = 'keyword'

    def __init__(self, keyword_file=None, cmd_keywords=None, mappings=None):
        self.keyword_file = keyword_file
        self.cmd_keywords = cmd_keywords or []
        self.keyword_dict = dict((mappings or {}).get('keyword', {}))
        self._counter = len(self.keyword_dict)
        self.load_keywords()

    def load_keywords(self):
        if self.keyword_file:
            if not os.path.isfile(self.keyword_file):
                print(f"[!] Keyword file not found: {self.keyword_file}", file=sys.stderr)
            else:
                try:
                    with open(self.keyword_file, 'r', encoding='utf-8') as f:
                        logging.info("Loading keywords from file: %s", self.keyword_file)
                        for line in f:
                            kw = line.split('#', 1)[0].strip().lower()
                            if not kw:
                                continue
                            if kw not in self.keyword_dict:
                                self.keyword_dict[kw] = self._next_fake()
                except Exception as e:
                    print(f"[!] Error reading keyword file: {e}", file=sys.stderr)
        if self.cmd_keywords:
            for keyword in self.cmd_keywords:
                kw = keyword.lower()
                if kw not in self.keyword_dict:
                    self.keyword_dict[kw] = self._next_fake()

    def _next_fake(self):
        self._counter += 1
        return f"keyword_{self._counter}"

    @property
    def mapping(self):
        return self.keyword_dict

    def scrub(self, text):
        for keyword, obfuscated in self.keyword_dict.items():
            text = re.sub(re.escape(keyword), obfuscated, text, flags=re.IGNORECASE)
        return text

    def is_loaded(self):
        return bool(self.keyword_dict)
