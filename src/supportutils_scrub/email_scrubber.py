# email_scrubber.py
import re

EMAIL_RE = re.compile(
    r'(?<![A-Za-z0-9._%+-])'
    r'([A-Za-z0-9][A-Za-z0-9._%+-]*[A-Za-z0-9]@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})'
    r'(?![A-Za-z0-9._%+-])'
)

_SKIP_SUFFIXES = (
    '.service', '.socket', '.timer', '.target', '.mount',
    '.slice', '.scope', '.path', '.device', '.conf', '.tmp',
    '.catalog',  
)

_SAFE_DOMAINS = {
    'example.com', 'example.org', 'example.net',
    'localhost', 'localhost.localdomain', 'localdomain',
}


class EmailScrubber:
    """Finds and replaces email addresses consistently """

    def __init__(self, mappings=None):
        self.email_dict = dict(mappings.get('email', {})) if mappings else {}
        self._counter = len(self.email_dict)

    def _get_fake_email(self, real_email):
        """Return a consistent fake email for a real one."""
        if real_email in self.email_dict:
            return self.email_dict[real_email]
        self._counter += 1
        fake = f"email_{self._counter}@scrubbed.local"
        self.email_dict[real_email] = fake
        return fake

    def scrub(self, text):
        """Replace all real email addresses in text. Returns scrubbed text."""
        def _replace(m):
            email = m.group(1)
            if any(email.endswith(s) for s in _SKIP_SUFFIXES):
                return email
            domain = email.split('@')[1].lower()
            if domain in _SAFE_DOMAINS:
                return email
            return self._get_fake_email(email)

        return EMAIL_RE.sub(lambda m: _replace(m), text)
