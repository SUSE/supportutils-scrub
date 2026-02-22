# username_scrubber.py

import re

class UsernameScrubber:
    """
    Handles the detection, mapping, and replacement of usernames.
    Excludes a predefined list of common system users from obfuscation.
    """
    EXCLUDED_USERS = {
        "root", "bin", "daemon", "lp", "mail", "news", "uucp", "games", "man",
        "wwwrun", "ftp", "nobody", "messagebus", "systemd-timesync", "uuidd",
        "at", "polkitd", "rpc", "nscd", "sshd", "statd", "ntp", "vnc", "hacluster",
        "ssm-user", "hapadm", "sapadm", "postfix", "pimuser", "rtkit", "pulse",
        "daaadm", "ubroker", "openslp", "scard", "ftpsecure", "cwagent", "aoc",
        "systemd-network", "tftp", "srvGeoClue", "flatpak", "mysql", "usbmux",
        "avahi", "dnsmasq", "nm-openconnect", "nm-openvpn", "sddm", "ronald",
        "svn", "citrixlog", "salt", "dockremap", "chrony", "laptop", "qemu", "tss",
        "wsdd", "gdm", "?", "(unknown)"
    }

    def __init__(self, username_dict):
        self.username_dict = username_dict

    def scrub(self, text):
        """Replaces usernames in a block of text based on the provided mapping."""
        sorted_users = sorted(self.username_dict.keys(), key=len, reverse=True)
        for username in sorted_users:
            text = re.sub(rf'\b{re.escape(username)}\b', self.username_dict[username], text)
        return text

    @staticmethod
    def _is_excluded(username):
        """Checks if a username should be excluded from obfuscation."""
        if username in UsernameScrubber.EXCLUDED_USERS:
            return True
        if len(username) == 6 and username.endswith("adm"):
            return True
        return False

    @staticmethod
    def extract_usernames_from_section(file_name, section_starts):
        """Extracts non-excluded usernames from /etc/passwd style sections."""
        usernames = set()
        try:
            with open(file_name, 'r', encoding='utf-8', errors='ignore') as file:
                in_section = False
                for line in file:
                    stripped_line = line.strip()
                    if stripped_line in section_starts:
                        in_section = True
                        continue

                    if in_section:
                        if not stripped_line or stripped_line.startswith("#"):
                            in_section = False
                            continue
                        
                        parts = stripped_line.split(':')
                        if parts:
                            username = parts[0]
                            if not UsernameScrubber._is_excluded(username):
                                usernames.add(username)
        except IOError:
            pass 
        
        return list(usernames)

    # Patterns shared between file-based and text-based extraction
    _LOG_PATTERNS = [
        re.compile(r"session opened for user (\w+)"),
        re.compile(r"\buser\s*=\s*([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r'acct="([^"]+)"'),
        re.compile(r'NCE/USER/[^/]+/([A-Za-z0-9._-]+)', re.IGNORECASE),
        # pam_unix(service:type): ... for [username]
        re.compile(r'pam_unix\([^)]+\):.*?\[([A-Za-z0-9._-]+)\]'),
        # unix_chkpwd: password check failed for user (username)
        re.compile(r'password check failed for user \(([A-Za-z0-9._-]+)\)'),
    ]

    @staticmethod
    def extract_usernames_from_messages(file_name):
        """Extracts non-excluded usernames from log files using regex."""
        usernames = set()
        try:
            with open(file_name, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    for pat in UsernameScrubber._LOG_PATTERNS:
                        match = pat.search(line)
                        if match:
                            username = match.group(1)
                            if not UsernameScrubber._is_excluded(username):
                                usernames.add(username)
        except IOError:
            pass

        return list(usernames)

    @staticmethod
    def extract_usernames_from_text(text):
        """Extracts non-excluded usernames from a text string using log patterns."""
        usernames = set()
        for line in text.splitlines():
            for pat in UsernameScrubber._LOG_PATTERNS:
                match = pat.search(line)
                if match:
                    username = match.group(1)
                    if not UsernameScrubber._is_excluded(username):
                        usernames.add(username)
        return list(usernames)
