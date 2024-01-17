# domain_scrubber.py

import re


class DomainScrubber:
    def __init__(self, domain_dict):
        self.domain_dict = domain_dict

    def scrub(self, text):
        for domain, obfuscated in self.domain_dict.items():
            text = text.replace(domain, obfuscated)
        return text
    
    def extract_domains_from_section(file_name, section_start):
        pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        domains = []
        try:
            with open(file_name, 'r') as file:
                section_found = False
                for line in file:
                    if section_start in line:
                        section_found = True
                        continue 
                    # Check if the line is the start of a new section, indicating the end of the current section
                    if section_found and "#==[" in line:
                        break
                    # Extract domains from the line if we are in the correct section
                    if section_found:
                        found_domains = re.findall(pattern, line)
                        domains.extend(found_domains)

        except FileNotFoundError:
            print(f"File not found: {file_name}")

        return domains
