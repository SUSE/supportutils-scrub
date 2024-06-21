# username_scrubber.py

import re

# username_scrubber.py

class UsernameScrubber:
    def __init__(self, username_dict):
        self.username_dict = username_dict


    def scrub(self, text):
        for username, obfuscated in self.username_dict.items():
            text = text.replace(username, obfuscated)
        return text
    

    @staticmethod
    def extract_usernames_from_section(file_name, section_start):
        excluded_users = {
            "root", "bin", "daemon", "lp", "mail", "news", "uucp", "games", "man",
            "wwwrun", "ftp", "nobody", "messagebus", "systemd-timesync", "uuidd",
            "at", "polkitd", "rpc", "nscd", "sshd", "statd", "ntp", "vnc", "hacluster",
            "ssm-user", "hapadm", "sapadm", "postfix", "pimuser", "rtkit", "pulse",
            "daaadm", "ubroker", "openslp", "scard", "ftpsecure", "cwagent", "aoc",
            "systemd-network", "tftp", "srvGeoClue", "flatpak", "mysql", "usbmux",
            "avahi", "dnsmasq", "nm-openconnect", "nm-openvpn", "sddm", "ronald",
            "svn", "citrixlog", "salt", "dockremap", "chrony", "laptop", "qemu", "tss",
            "wsdd"
        }

        def is_excluded(username):
            if username in excluded_users:
                return True
            if len(username) == 6 and username.endswith("adm"):
                return True
            return False

        with open(file_name, 'r') as file:
            lines = file.readlines()

        in_section = False
        usernames = []

        for line in lines:
            if line.strip() == section_start:
                in_section = True
                continue

            if in_section:
                if line.strip() == "" or line.startswith("#"):
                    break
                username = line.split(':')[0]
                if not is_excluded(username):
                    usernames.append(username)
        
        return usernames

