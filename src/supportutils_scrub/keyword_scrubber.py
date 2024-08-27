import random
import logging
import re

class KeywordScrubber:
    def __init__(self, keyword_file=None, cmd_keywords=None):
        self.keyword_file = keyword_file
        self.cmd_keywords = cmd_keywords or []
        self.keyword_dict = {}
        self.load_keywords()

    def load_keywords(self):
        # Load from file
        if self.keyword_file:
            logging.info(f"Attempting to load keywords from file: {self.keyword_file}")
            try:
                if not os.path.exists(self.keyword_file):
                    logging.error(f"Keyword file does not exist: {self.keyword_file}")
                    raise FileNotFoundError(f"Keyword file not found: {self.keyword_file}")

                with open(self.keyword_file, 'r') as file:
                    for line in file:
                        keyword = line.strip()
                        if keyword:
                            logging.info(f"Loading keyword from file: {keyword}")
                            self.keyword_dict[keyword.lower()] = self._generate_obfuscated_keyword()
                logging.info(f"Successfully loaded {len(self.keyword_dict)} keywords from file.")
            except Exception as e:
                logging.error(f"Error loading keyword file: {e}")
                raise

        # Load from command line arguments
        if self.cmd_keywords:
            logging.info("Loading keywords from command line arguments.")
            for keyword in self.cmd_keywords:
                if keyword.lower() not in self.keyword_dict:
                    logging.info(f"Loading keyword from command line: {keyword}")
                    self.keyword_dict[keyword.lower()] = self._generate_obfuscated_keyword()
            logging.info(f"Total keywords loaded from command line: {len(self.cmd_keywords)}")

        # Final keyword count
        logging.info(f"Total unique keywords loaded: {len(self.keyword_dict)}")

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
