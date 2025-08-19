# domain_scrubber.py

import re
from typing import Set, Dict, List, Optional, Tuple, Iterable, Match

LABEL = r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
DOMAIN_RE = re.compile(rf"(?<![\w-])({LABEL}(?:\.{LABEL})+)(?![\w-])", re.IGNORECASE)

_SINGLE_LABEL_BAN = {
    "local", "localhost", "internal", "intranet", "corp", "lan", "home",
    "net", "org", "com", "edu", "gov", "mil", "int", "arpa"
}

def _norm(d: str) -> str:
    """Normalizes a domain by stripping whitespace, trailing dots, and converting to lowercase."""
    return d.strip().rstrip(".").lower()

def _labels_count(d: str) -> int:
    """Counts the number of labels in a domain."""
    return _norm(d).count(".") + 1

def _is_valid_domain(d: str) -> bool:
    """Performs basic validation on a domain string."""
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
    return True

def _sort_specific_first(domains: Iterable[str]) -> List[str]:
    """Sorts domains by the number of labels, then by length, to ensure most-specific comes first."""
    uniq = {_norm(d) for d in domains if _is_valid_domain(d)}
    return sorted(uniq, key=lambda s: (_labels_count(s), len(s)), reverse=True)

class DomainScrubber:


    def __init__(self, domain_dict: Dict[str, str]):
        # Normalize keys and filter out any invalid domain entries
        self.domain_dict: Dict[str, str] = {
            _norm(real): fake
            for real, fake in (domain_dict or {}).items()
            if _is_valid_domain(real)
        }

        # Build one compiled regex alternation for all domains, ordered by specificity
        self._ordered_domains = _sort_specific_first(self.domain_dict.keys())
        if self._ordered_domains:
            alternates = "|".join(re.escape(d) for d in self._ordered_domains)
            # Use a negative lookbehind/ahead for safer boundaries; ignore case
            self._re = re.compile(rf"(?<![\w-])(?:{alternates})(?![\w-])", re.IGNORECASE)
        else:
            self._re = None

    def scrub(self, text: str) -> str:
        """Replaces all known domains in a block of text using a single regex pass."""
        if not self._re:
            return text

        def _replacer(match: Match) -> str:
            """Callback function for re.sub to find the correct replacement."""
            found_domain = _norm(match.group(0))
            return self.domain_dict.get(found_domain, match.group(0))

        return self._re.sub(_replacer, text)


    @staticmethod
    def extract_domains_from_text(text: str) -> List[str]:
        """
        Finds FQDNs in text and extracts only the valid, multi-label domain parts.
        For example, from 'metadata.google.internal', it extracts 'google.internal'.
        It also extracts parent domains (e.g., from 'a.b.c.com', it adds 'b.c.com' and 'c.com').
        """
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

        return _sort_specific_first(all_domain_parts)

    @staticmethod
    def extract_domains_from_file_section(file_handle, section_start: str) -> List[str]:
        """
        Extracts domains from a specific section of a file, stopping at the next header.
        """
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
        """
        Add the domain and all parent domains to 'out'.
        e.g. 'lab.new.suse.org' -> {'lab.new.suse.org','new.suse.org','suse.org'}
        """
        if not domain:
            return
        d = domain.strip().lower().strip(".")
        if not d or "." not in d:
            return
        labels = d.split(".")
        for i in range(len(labels) - 1):
            out.add(".".join(labels[i:]))


