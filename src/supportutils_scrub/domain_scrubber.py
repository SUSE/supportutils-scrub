#domain_scruber.py

import re

class DomainScrubber:
    def __init__(self, domain_dict):
        self.domain_dict = domain_dict

    def scrub(self, text):
        sorted_domains = sorted(self.domain_dict.keys(), key=len, reverse=True)

        for domain in sorted_domains:
            escaped = re.escape(domain)
            # Replace full matches or boundaries (e.g., end of hostname)
            text = re.sub(rf'\b{escaped}\b', self.domain_dict[domain], text)
        return text    

    @staticmethod
    def extract_domains_from_section(file_obj, section_start):
        pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        excluded_domains = {"suse.com", "www.suse.com", "ntp.drift", "ntp.keys"}
        domains = set()

        section_found = False
        for line in file_obj:
            if section_start in line:
                section_found = True
                continue 
            if section_found and "#==[" in line:
                break
            if section_found:
                found_domains = re.findall(pattern, line)
                for domain in found_domains:
                    if domain in excluded_domains:
                        continue
                    labels = domain.split(".")
                    if len(labels) >= 2:
                        # Drop the first label (hostname), keep remaining as domains
                        for i in range(1, len(labels) - 1):
                            domain_segment = ".".join(labels[i:])
                            domains.add(domain_segment)
                        domains.add(".".join(labels[1:]))  # Always keep full domain minus host

        return domains

    @staticmethod
    def extract_domains_from_hosts(file_obj, section_start):
        pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        domains = set()
        section_found = False
        for line in file_obj:
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
                                # Split into labels and discard the first segment (hostname)
                                labels = domain.split('.')
                                if len(labels) >= 2:
                                    stripped_domain = '.'.join(labels[1:])  # drop the hostname part
                                    # Build all subdomains 
                                    for i in range(len(labels) - 1):
                                        subdomain = '.'.join(labels[i+1:])
                                        domains.add(subdomain)
        return list(domains)

    @staticmethod
    def extract_domains_from_resolv_conf(file_obj, section_start):
        domains = set()
        section_found = False
        for line in file_obj:
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
        return list(domains)
