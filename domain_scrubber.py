# scrubber/domain_scrubber.py

import re


class DomainScrubber:
    def __init__(self):
        self.domain_dict = {}
        self.fake_domain_counter = 0

    def scrub_domain(self, domain):
        """
        Obfuscate a domain name. Each domain gets a unique fake domain.
        """
        if domain in self.domain_dict:
            return self.domain_dict[domain]
        obfuscated_domain = self.generate_fake_domain()
        self.domain_dict[domain] = obfuscated_domain
        return obfuscated_domain

    def generate_fake_domain(self):
        """
        Generate a unique fake domain name.
        """
        fake_domain = f"fake.domain_{self.fake_domain_counter}"
        self.fake_domain_counter += 1
        return fake_domain

    @staticmethod
    def extract_domains(text):
        """
        Extract domain names from a given text.
        """
        domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        return re.findall(domain_pattern, text)

