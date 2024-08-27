# hostname_scrubber.py

import re

class HostnameScrubber:
    def __init__(self, hostname_dict):
        self.hostname_dict = hostname_dict

    def scrub(self, text):
        for hostname, obfuscated in self.hostname_dict.items():
            text = text.replace(hostname, obfuscated)
        return text
    
    @staticmethod
    def extract_hostnames_from_hosts(file_path):
        hostnames = []
        excluded_hostnames = {
            "localhost", "ipv6-localhost", "ipv6-loopback", 
            "ipv6-localnet", "ipv6-mcastprefix", "ipv6-allnodes", 
            "ipv6-allrouters", "ipv6-allhosts"
        }
        with open(file_path, 'r') as file:
            in_hosts_section = False
            for line in file:
                if line.startswith('# /etc/hosts'):
                    in_hosts_section = True
                    continue
                if line.startswith('# /etc/host.conf'):
                    break
                if in_hosts_section:
                    if line.strip() == "" or line.startswith('#'):
                        continue
                    fields = re.split(r'\s+', line.strip())
                    if len(fields) >= 2:
                        second_field = fields[1] if '-' in fields[1] else fields[1].split('.')[0]
                        if second_field not in excluded_hostnames:
                            hostnames.append(second_field)
                    if len(fields) >= 3:
                        third_field = fields[2] if '-' in fields[2] else fields[2].split('.')[0]
                        if third_field not in excluded_hostnames:
                            hostnames.append(third_field)
        return hostnames

    @staticmethod
    def extract_hostnames_from_hostname_section(file_path):
        hostnames = []
        excluded_hostnames = {
            "localhost", "ipv6-localhost", "ipv6-loopback", 
            "ipv6-localnet", "ipv6-mcastprefix", "ipv6-allnodes", 
            "ipv6-allrouters", "ipv6-allhosts"
        }
        with open(file_path, 'r') as file:
            in_hostname_section = False
            for line in file:
                if line.startswith('# /bin/hostname'):
                    in_hostname_section = True
                    continue
                if in_hostname_section:
                    if line.strip() == "" or line.startswith('#'):
                        continue
                    hostname = line.strip()
                    if hostname not in excluded_hostnames:
                        hostnames.append(hostname)
                    break  # Only need to process the first line of the hostname section
        return hostnames

    @staticmethod
    def build_hostname_dict(hostnames):
        hostname_dict = {}
        for index, hostname in enumerate(hostnames, start=1):
            hostname_dict[hostname] = f'hostname{index}'
        return hostname_dict
