# domain_scrubber.py

import re
from typing import Set, Dict, List, Optional, Tuple, Iterable, Match
from supportutils_scrub.scrubber import Scrubber

LABEL = r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
DOMAIN_RE = re.compile(rf"(?<![\w-])({LABEL}(?:\.{LABEL})+)(?![\w-])", re.IGNORECASE)

_DC_RE = re.compile(r'(DC=[A-Za-z0-9-]+(?:,DC=[A-Za-z0-9-]+)+)', re.IGNORECASE)

_SINGLE_LABEL_BAN = {
    "local", "localhost", "internal", "intranet", "corp", "lan", "home",
    "net", "org", "com", "edu", "gov", "mil", "int", "arpa"
}

_VALID_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "int", "arpa",
    "io", "co", "biz", "info", "name", "mobi", "tel", "cat", "jobs", "pro",
    "aero", "coop", "museum", "travel",
    "cloud", "tech", "dev", "app", "ai", "online", "digital", "global",
    "email", "zone", "host", "data", "software",
    "us", "eu",
    "ac", "ad", "ae", "af", "ag", "al", "am", "ao", "ar", "at", "au", "az",
    "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bm", "bn", "bo",
    "br", "bs", "bt", "bw", "by", "bz",
    "ca", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "cr",
    "cu", "cv", "cy", "cz",
    "de", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "er", "es", "et",
    "fi", "fj", "fo", "fr",
    "ga", "gd", "ge", "gh", "gm", "gn", "gr", "gt", "gw", "gy",
    "hk", "hn", "hr", "ht", "hu",
    "id", "ie", "il", "in", "iq", "ir", "is", "it",
    "jm", "jo", "jp",
    "ke", "kg", "kh", "km", "kn", "kp", "kr", "kw", "kz",
    "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly",
    "ma", "mc", "md", "me", "mg", "mk", "ml", "mm", "mn", "mr", "mt", "mu",
    "mv", "mw", "mx", "my", "mz",
    "na", "ne", "ng", "ni", "nl", "no", "np", "nr", "nz",
    "om",
    "pa", "pe", "ph", "pk", "pl", "pt", "pw", "py",
    "qa",
    "ro", "rs", "ru", "rw",
    "sa", "sb", "sc", "sd", "se", "sg", "si", "sk", "sl", "sm", "sn", "so",
    "sr", "ss", "st", "sv", "sy", "sz",
    "td", "tg", "th", "tj", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tz",
    "ua", "ug", "uk", "uy", "uz",
    "va", "vc", "ve", "vn", "vu",
    "ws",
    "ye",
    "za", "zm", "zw",
})

def _norm(d: str) -> str:
    return d.strip().rstrip(".").lower()

def _labels_count(d: str) -> int:
    return _norm(d).count(".") + 1

def _is_valid_domain(d: str) -> bool:
    d = _norm(d)
    if "." not in d:
        return False
    if d in _SINGLE_LABEL_BAN:
        return False
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", d):
        return False
    parts = d.split(".")
    if any(len(p) == 0 for p in parts):
        return False
    for p in parts:
        if len(p) > 63:
            return False
        if p.startswith("-") or p.endswith("-"):
            return False
        if not re.fullmatch(r"[a-zA-Z0-9-]+", p):
            return False
    if parts[-1].lower() not in _VALID_TLDS:
        return False
    return True

def _sort_specific_first(domains: Iterable[str]) -> List[str]:
    """Sort domains most-specific first (by label count, then length)."""
    uniq = {_norm(d) for d in domains if _is_valid_domain(d)}
    return sorted(uniq, key=lambda s: (_labels_count(s), len(s)), reverse=True)

def _dc_to_domain(dc_str: str) -> str:
    return '.'.join(re.findall(r'(?i)DC=([A-Za-z0-9-]+)', dc_str)).lower()

def _domain_to_dc(domain: str) -> str:
    return ','.join(f'DC={label}' for label in domain.split('.'))

class DomainScrubber(Scrubber):
    name = 'domain'

    def __init__(self, domain_dict: Dict[str, str]):
        self.domain_dict: Dict[str, str] = {
            _norm(real): fake
            for real, fake in (domain_dict or {}).items()
            if _is_valid_domain(real)
        }

        self._ordered_domains = _sort_specific_first(self.domain_dict.keys())
        if self._ordered_domains:
            alternates = "|".join(re.escape(d) for d in self._ordered_domains)
            self._re = re.compile(rf"(?<![\w-])(?:{alternates})(?![\w-])", re.IGNORECASE)
        else:
            self._re = None

        self._dc_dict: Dict[str, str] = {}
        for real, fake in self.domain_dict.items():
            self._dc_dict[_domain_to_dc(real).lower()] = _domain_to_dc(fake)
        if self._dc_dict:
            dc_alts = "|".join(re.escape(k) for k in sorted(self._dc_dict, key=len, reverse=True))
            self._dc_re = re.compile(rf'(?:{dc_alts})', re.IGNORECASE)
        else:
            self._dc_re = None

    @property
    def mapping(self):
        return self.domain_dict

    def scrub(self, text: str) -> str:
        if self._re:
            def _replacer(match: Match) -> str:
                found_domain = _norm(match.group(0))
                return self.domain_dict.get(found_domain, match.group(0))
            text = self._re.sub(_replacer, text)

        if self._dc_re:
            text = self._dc_re.sub(
                lambda m: self._dc_dict.get(m.group(0).lower(), m.group(0)),
                text
            )

        return text


    @staticmethod
    def extract_domains_from_text(text: str) -> List[str]:
        """Extract valid domains from text, including parent domains."""
        if not text:
            return []

        all_domain_parts = set()
        matches = DOMAIN_RE.finditer(text)
        for m in matches:
            fqdn = _norm(m.group(1))
            if not _is_valid_domain(fqdn):
                continue

            parts = fqdn.split('.')

            for i in range(1, len(parts) - 1):
                parent_domain = '.'.join(parts[i:])
                if _is_valid_domain(parent_domain):
                    all_domain_parts.add(parent_domain)

        for m in _DC_RE.finditer(text):
            domain = _dc_to_domain(m.group(1))
            if _is_valid_domain(domain):
                DomainScrubber._add_domain_and_parents(domain, all_domain_parts)

        return _sort_specific_first(all_domain_parts)

    @staticmethod
    def extract_domains_from_file_section(file_handle, section_start: str) -> List[str]:
        """Extract domains from a specific section of a file, stopping at the next section header."""
        all_domains = set()
        in_section = False
        try:
            file_handle.seek(0)
            for line in file_handle:
                stripped_line = line.strip()
                if stripped_line == section_start:
                    in_section = True
                    continue
                
                if in_section and stripped_line.startswith("#"):
                    break 
                
                if in_section:
                    content = line.split("#", 1)[0]
                    all_domains.update(DomainScrubber.extract_domains_from_text(content))
        except Exception:
           
            pass
        return _sort_specific_first(all_domains)

    @staticmethod
    def _add_domain_and_parents(domain: str, out: Set[str]) -> None:
        """Add a domain and all its parent domains to out."""
        if not domain:
            return
        d = domain.strip().lower().strip(".")
        if not d or "." not in d:
            return
        labels = d.split(".")
        for i in range(len(labels) - 1):
            out.add(".".join(labels[i:]))


