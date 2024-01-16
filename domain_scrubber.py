# domain_scrubber.py

import re


class DomainScrubber:
    def __init__(self, domain_dict):
        self.domain_dict = domain_dict

    def scrub(self, text):
        for domain, obfuscated in self.domain_dict.items():
            text = text.replace(domain, obfuscated)
        return text
    