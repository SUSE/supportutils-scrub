# username_scrubber.py

import re
from supportutils_scrub.fastsub import ALNUM, fold, key, sub_folded
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

    # An account may carry the name of a system directory or an everyday log
    # word ("boot"). Replacing it as a whole word rewrites /boot/grub2 and
    # "first boot" in every file, so such a name is never learned, and one
    # an older mapping file carries is not replaced either.
    COMMON_WORDS = {
        "boot", "etc", "home", "opt", "srv", "tmp", "usr", "var", "proc", "sys",
        "dev", "run", "mnt", "media", "lib", "lib64", "sbin", "efi", "grub",
        "grub2", "kernel", "system", "default", "local", "user", "users",
        "guest", "test", "data", "backup", "admin", "service", "snapshots",
    }

    def __init__(self, username_dict):
        self.username_dict = username_dict
        # Lowercased and matched case-insensitively with only letters and
        # digits as neighbours: EXAMPLE\JDOE, Jdoe, backup_jdoe.tar and
        # /home/jdoe_old all carry the account.
        self._lookup = {k.lower(): v for k, v in username_dict.items()
                        if k.lower() not in self.COMMON_WORDS}
        # Trie-regex: factoring shared prefixes lets the C engine dispatch by
        # character (O(text)), instead of a flat alternation backtracking through
        # 1000+ usernames at every position. The callback fires only on matches.
        self._re = None
        trie = build_trie_pattern(self._lookup.keys())
        if trie:
            self._re = re.compile(r'(?<![A-Za-z0-9])(?:' + trie + r')(?![A-Za-z0-9])',
                                  re.IGNORECASE)
        # The same list for the lowercase copy of a text, where `re` can
        # skip by first character (see fastsub.sub_folded). Only for plain
        # ASCII names: the copy is not a faithful stand-in for others.
        self._re_low = None
        if trie and all(ord(ch) < 128 for k in self._lookup for ch in k):
            self._re_low = re.compile(r'(?:' + trie + r')(?![a-z0-9])')

    @property
    def mapping(self):
        return self.username_dict

    def scrub(self, text):
        if not self._re:
            return text
        low = fold(text) if self._re_low else None
        if low is None:
            return self._re.sub(lambda m: self._lookup[key(m.group(0))], text)
        return sub_folded(self._re_low, ALNUM, self._lookup, text, low)

    @staticmethod
    def _is_excluded(username):
        if len(username) < 3 or username.isdigit():
            return True
        if username in UsernameScrubber.EXCLUDED_USERS:
            return True
        if username.lower() in UsernameScrubber.COMMON_WORDS:
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
        re.compile(r"session opened for user ([\w.@-]+?)(?=[(\s]|$)"),
        # lower case only: sudo's USER= is the target account (root, postgres),
        # not the person
        re.compile(r"(?<![A-Za-z])(?:user|logname)\s*=\s*([A-Za-z0-9._-]+)"),
        re.compile(r"\bsudo(?:\[\d+\])?:\s+([A-Za-z0-9._@-]+)\s+:"),
        re.compile(r"\bAccepted \S+ for ([A-Za-z0-9._@-]+) from "),
        re.compile(r'acct="([^"]+)"'),
        re.compile(r'NCE/USER/[^/]+/([A-Za-z0-9._-]+)', re.IGNORECASE),
        re.compile(r'pam_unix\([^)]+\):.*?\[([A-Za-z0-9._-]+)\]'),
        re.compile(r'password check failed for user \(([A-Za-z0-9._-]+)\)'),
    ]

    # Every line any _LOG_PATTERNS entry can match contains one of these
    # substrings, so locating them with str.find and running the patterns
    # only on the enclosing lines is an exact-semantics fast path.
    _LOG_TRIGGERS = ('user', 'logname', 'acct="', 'pam_unix', 'sudo', 'accepted ')

    @staticmethod
    def _extract_from_log_lines(lines):
        usernames = set()
        for line in lines:
            for pat in UsernameScrubber._LOG_PATTERNS:
                for match in pat.finditer(line):
                    username = match.group(1).rstrip('.')
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
