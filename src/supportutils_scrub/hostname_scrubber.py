# hostname_scrubber.py

import re

class HostnameScrubber:
    def __init__(self, hostname_dict):
        self.hostname_dict = hostname_dict

    def scrub(self, text):
        for hostname in sorted(self.hostname_dict, key=len, reverse=True):
            obfuscated = self.hostname_dict[hostname]
            pattern = r'\b' + re.escape(hostname) + r'(?=\s|$|\.|\:|\/|\,|\;)'
            text = re.sub(pattern, obfuscated, text)         
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
                    if '#' in line:
                        line = line.split('#')[0]

                    fields = re.split(r'\s+', line.strip())
                    for field in fields[1:]:
                        short_name = field.split('.')[0]
                        if len(short_name) < 4:
                            continue
                        if short_name not in excluded_hostnames:
                            hostnames.append(short_name)

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
                    short_name = hostname.split('.')[0]
                    if short_name not in excluded_hostnames:
                        hostnames.append(short_name)
                    
                    break  
        return hostnames

    @staticmethod
    def extract_hostnames_from_text(text):
        """
        Extracts hostnames from a log text string.
        Handles:
          - NFS server lines: 'nfs: server hostname.domain.tld'
          - RFC 5424 syslog: 'TIMESTAMP HOSTNAME service: ...' (hostname repeated >= 3 lines)
        """
        excluded = {
            "localhost", "ipv6-localhost", "ipv6-loopback",
            "ipv6-localnet", "ipv6-mcastprefix", "ipv6-allnodes",
            "ipv6-allrouters", "ipv6-allhosts",
        }
        hostnames = set()

        # NFS server: "nfs: server hostname.domain.tld [not responding, ...]"
        for m in re.finditer(r'nfs: server ([\w][\w.-]*)', text):
            short = m.group(1).split('.')[0]
            if len(short) >= 3 and short not in excluded:
                hostnames.add(short)

        # RFC 5424 syslog timestamp + hostname: "2026-02-17T01:50:02+01:00 HOSTNAME service: ..."
        counts = {}
        for m in re.finditer(
            r'^\d{4}-\d{2}-\d{2}T[\d:.+-]+\s+([\w][\w-]*)\b', text, re.MULTILINE
        ):
            h = m.group(1)
            if len(h) >= 3 and h not in excluded:
                counts[h] = counts.get(h, 0) + 1
        for h, count in counts.items():
            if count >= 3:
                hostnames.add(h)

        return list(hostnames)

    @staticmethod
    def build_hostname_dict(hostnames):
        hostname_dict = {}
        seen = set()
        for hostname in hostnames:
            short = hostname.split('.')[0]
            if short not in seen:
                seen.add(short)
                hostname_dict[short] = f'hostname{len(seen)-1}'
        return hostname_dict
