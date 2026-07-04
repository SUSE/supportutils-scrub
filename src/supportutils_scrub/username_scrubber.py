# username_scrubber.py

import re
from supportutils_scrub.scrubber import Scrubber
from supportutils_scrub.trie_re import build_trie_pattern

class UsernameScrubber(Scrubber):
    name = 'user'

    EXCLUDED_USERS = {
        "root", "bin", "daemon", "lp", "mail", "news", "uucp", "games", "man",
        "wwwrun", "ftp", "nobody", "messagebus", "systemd-timesync", "uuidd",
        "at", "polkitd", "rpc", "nscd", "sshd", "statd", "ntp", "vnc", "hacluster",
        "ssm-user", "hapadm", "sapadm", "postfix", "pimuser", "rtkit", "pulse",
        "daaadm", "ubroker", "openslp", "scard", "ftpsecure", "cwagent", "aoc",
        "systemd-network", "tftp", "srvGeoClue", "flatpak", "mysql", "usbmux",
        "avahi", "dnsmasq", "nm-openconnect", "nm-openvpn", "sddm",
        "svn", "citrixlog", "salt", "dockremap", "chrony", "laptop", "qemu", "tss",
        "wsdd", "gdm", "zabbix", "vscan", "lldpd", "?", "(unknown)",
        "uid", "gid", "pid", "sudo", "su", "login", "session", "auth",
    }

    def __init__(self, username_dict):
        self.username_dict = username_dict
        # Trie-regex: factoring shared prefixes lets the C engine dispatch by
        # character (O(text)), instead of a flat alternation backtracking through
        # 1000+ usernames at every position. The callback fires only on matches.
        self._re = None
        if username_dict:
            self._re = re.compile(r'\b(?:' + build_trie_pattern(username_dict.keys()) + r')\b')

    @property
    def mapping(self):
        return self.username_dict

    def scrub(self, text):
        if not self._re:
            return text
        return self._re.sub(lambda m: self.username_dict[m.group(0)], text)

    @staticmethod
    def _is_excluded(username):
        if len(username) < 3:
            return True
        if username in UsernameScrubber.EXCLUDED_USERS:
            return True
        if len(username) == 6 and username.endswith("adm"):
            return True
        return False

    @staticmethod
    def extract_usernames_from_section(file_name, section_starts):
        """Extract non-excluded usernames from /etc/passwd style sections."""
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
                            try:
                                if int(parts[2]) < 1000:
                                    continue
                            except (IndexError, ValueError):
                                pass
                            if not UsernameScrubber._is_excluded(username):
                                usernames.add(username)
        except IOError:
            pass 
        
        return list(usernames)

    _LOG_PATTERNS = [
        re.compile(r"session opened for user (\w+)"),
        re.compile(r"\b(?:user|logname)\s*=\s*([A-Za-z0-9._-]+)", re.IGNORECASE),
        re.compile(r'acct="([^"]+)"'),
        re.compile(r'NCE/USER/[^/]+/([A-Za-z0-9._-]+)', re.IGNORECASE),
        re.compile(r'pam_unix\([^)]+\):.*?\[([A-Za-z0-9._-]+)\]'),
        re.compile(r'password check failed for user \(([A-Za-z0-9._-]+)\)'),
    ]

    # Every line any _LOG_PATTERNS entry can match contains one of these
    # substrings, so locating them with str.find and running the 6 patterns
    # only on the enclosing lines is an exact-semantics fast path.
    _LOG_TRIGGERS = ('user', 'logname', 'acct="', 'pam_unix')

    @staticmethod
    def _extract_from_log_lines(lines):
        usernames = set()
        for line in lines:
            for pat in UsernameScrubber._LOG_PATTERNS:
                match = pat.search(line)
                if match:
                    username = match.group(1)
                    if not UsernameScrubber._is_excluded(username):
                        usernames.add(username)
        return usernames

    @staticmethod
    def extract_usernames_from_messages(file_name):
        """Extract non-excluded usernames from log files."""
        try:
            with open(file_name, 'r', encoding='utf-8', errors='ignore') as file:
                text = file.read()
        except IOError:
            return []
        return UsernameScrubber.extract_usernames_from_text(text)

    @staticmethod
    def extract_usernames_from_text(text):
        """Extract non-excluded usernames from a text string using log patterns."""
        lower = text.lower()
        seen_starts = set()
        lines = []
        for trigger in UsernameScrubber._LOG_TRIGGERS:
            pos = lower.find(trigger)
            while pos != -1:
                line_start = lower.rfind('\n', 0, pos) + 1
                if line_start not in seen_starts:
                    seen_starts.add(line_start)
                    line_end = lower.find('\n', pos)
                    lines.append(text[line_start:line_end if line_end != -1 else len(text)])
                pos = lower.find(trigger, pos + 1)
        return list(UsernameScrubber._extract_from_log_lines(lines))
