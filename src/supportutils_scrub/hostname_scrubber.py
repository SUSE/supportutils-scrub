# hostname_scrubber.py

import re
from supportutils_scrub.scrubber import Scrubber

class HostnameScrubber(Scrubber):
    name = 'hostname'

    def __init__(self, hostname_dict):
        self.hostname_dict = hostname_dict
        self._re = None
        if hostname_dict:
            sorted_hosts = sorted(hostname_dict.keys(), key=len, reverse=True)
            alts = '|'.join(re.escape(h) for h in sorted_hosts)
            self._re = re.compile(r'\b(?:' + alts + r')\b')

    @property
    def mapping(self):
        return self.hostname_dict

    def scrub(self, text):
        if not self._re:
            return text
        return self._re.sub(lambda m: self.hostname_dict[m.group(0)], text)
    


    @staticmethod
    def extract_hostnames_from_hosts(file_path):
        hostnames = []
        excluded_hostnames = {
            "localhost", "ipv6-localhost", "ipv6-loopback",
            "ipv6-localnet", "ipv6-mcastprefix", "ipv6-allnodes",
            "ipv6-allrouters", "ipv6-allhosts",
            "ip6-localhost", "ip6-loopback",
            "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
            "ip6-allrouters", "ip6-allhosts",
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
            "ipv6-allrouters", "ipv6-allhosts",
            "ip6-localhost", "ip6-loopback",
            "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes",
            "ip6-allrouters", "ip6-allhosts",
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
        """Extract hostnames from NFS server lines and RFC 5424 syslog timestamps."""
        excluded = {
            "localhost", "ipv6-localhost", "ipv6-loopback",
            "ipv6-localnet", "ipv6-mcastprefix", "ipv6-allnodes",
            "ipv6-allrouters", "ipv6-allhosts",
        }
        hostnames = set()

        for m in re.finditer(r'nfs: server ([\w][\w.-]*)', text):
            short = m.group(1).split('.')[0]
            if len(short) >= 3 and short not in excluded:
                hostnames.add(short)

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
