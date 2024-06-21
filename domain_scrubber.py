# domain_scrubber.py

import re


class DomainScrubber:
    def __init__(self, domain_dict):
        self.domain_dict = domain_dict


    def scrub(self, text):
        sorted_domains = sorted(self.domain_dict.keys(), key=len, reverse=True)
        for domain in sorted_domains:
            obfuscated = self.domain_dict[domain]
            text = text.replace(domain, obfuscated)
        return text
    

    @staticmethod
    def extract_domains_from_section(file_name, section_start):
        pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        excluded_domains = {"suse.com", "www.suse.com", "ntp.drift", "ntp.keys"}
        domains = []
        try:
            with open(file_name, 'r') as file:
                section_found = False
                for line in file:
                    if section_start in line:
                        section_found = True
                        continue 
                    if section_found and "#==[" in line:
                        break
                    if section_found:
                        found_domains = re.findall(pattern, line)
                        found_domains = [domain for domain in found_domains if domain not in excluded_domains]
                        domains.extend(found_domains)
        except FileNotFoundError:
            print(f"File not found: {file_name}")
        return domains


    @staticmethod
    def extract_domains_from_hosts(file_name, section_start):
        pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        domains = set()
        try:
            with open(file_name, 'r', encoding='utf-8', errors='ignore') as file:
                section_found = False
                for line in file:
                    if section_start in line:
                        section_found = True
                        continue
                    if section_found and "#==[" in line:
                        break
                    if section_found:
                        parts = line.split()
                        if len(parts) > 2:  # Ensure there are at least two fields after the IP address
                            for part in parts[1:]:
                                if '.' in part:
                                    found_domains = re.findall(pattern, part)
                                    for domain in found_domains:
                                        if domain.split('.')[0] not in parts[1:]:
                                            segments = domain.split('.')
                                            for i in range(len(segments) - 1):
                                                domain_segment = '.'.join(segments[i:])
                                                domains.add(domain_segment)
        except FileNotFoundError:
            print(f"File not found: {file_name}")
        
        return list(domains)
    

    @staticmethod
    def extract_domains_from_resolv_conf(file_name, section_start):
        domains = set()
        try:
            with open(file_name, 'r', encoding='utf-8', errors='ignore') as file:
                section_found = False
                for line in file:
                    if section_start in line:
                        section_found = True
                        continue
                    if section_found and "#==[" in line:
                        break
                    if section_found:
                        line = line.strip()
                        if line.startswith("search"):
                            parts = line.split()[1:]  # Skip the 'search' keyword
                            for part in parts:
                                segments = part.split('.')
                                for i in range(len(segments) - 1):
                                    domain_segment = '.'.join(segments[i:])
                                    domains.add(domain_segment)
                        else:
                            found_domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', line)
                            for domain in found_domains:
                                segments = domain.split('.')
                                for i in range(len(segments) - 1):
                                    domain_segment = '.'.join(segments[i:])
                                    domains.add(domain_segment)
        except FileNotFoundError:
            print(f"File not found: {file_name}")

        return list(domains)