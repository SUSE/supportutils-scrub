# domain_scrubber.py

import re

class DomainScrubber:
    def __init__(self):
        self.domain_dict = {}
        self.fake_domain_counter = 0
        self.regex_pattern = r'\b(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}\b'
        self.exclusions = ["target.wants", "org.opensuse", "org.freedesktop", "net.ipv6", "raw.sig", "org.fedoraproject" ]

    def scrub_domain(self, domain):
        """
        Obfuscate a domain name. Each domain gets a unique fake domain.
        """
        if domain not in self.domain_dict:
            obfuscated_domain = f"fakeDomain{self.fake_domain_counter}.com"
            self.domain_dict[domain] = obfuscated_domain
            self.fake_domain_counter += 1
        return self.domain_dict[domain]

    def extract_and_scrub_domains(self, text):
        """
        Extract domain names from a given text and scrub them, excluding specified patterns.
        """
        for domain in re.findall(self.regex_pattern, text):
            # Skip domains that contain any part of the exclusion patterns
            if any(exclusion in domain for exclusion in self.exclusions):
                continue

            obfuscated_domain = self.scrub_domain(domain)
            text = text.replace(domain, obfuscated_domain)

        #print("Domain mappings:", self.domain_dict)
        return text
