# email_scrubber.py
import re
from supportutils_scrub.scrubber import Scrubber, is_pseudonym
from supportutils_scrub.domain_scrubber import is_preserved_domain

EMAIL_RE = re.compile(
    r'(?<![A-Za-z0-9._%+-])'
    r'([A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})'
    # A '.' ending the sentence is not part of the address.
    r'(?![A-Za-z0-9_%+-]|\.[A-Za-z0-9])'
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

# A local part that is already a pseudonym is left alone. URL userinfo is
# scrubbed earlier in the chain, and "SCRUBBED_LOGIN_1@repo.example.com" then
# matches EMAIL_RE exactly — re-scrubbing it as a whole would collapse a login
# and the host it authenticates against into one value and take the host out
# of the domain scrubber's hands.


class EmailScrubber(Scrubber):
    name = 'email'
    """Finds and replaces email addresses consistently """

    def __init__(self, mappings=None, deterministic=False):
        self.email_dict = dict(mappings.get('email', {})) if mappings else {}
        self._counter = len(self.email_dict)
        self.deterministic = deterministic

    @property
    def mapping(self):
        return self.email_dict

    def _get_fake_email(self, real_email):
        """Return a consistent fake email for a real one."""
        if real_email in self.email_dict:
            return self.email_dict[real_email]
        if self.deterministic:
            from supportutils_scrub.det import dhash
            fake = f"email_{dhash(real_email)}@scrubbed.local"
        else:
            self._counter += 1
            fake = f"email_{self._counter}@scrubbed.local"
        self.email_dict[real_email] = fake
        return fake

    def scrub(self, text):
        """Replace all real email addresses in text. Returns scrubbed text."""
        if '@' not in text:
            return text

        def _replace(m):
            email = m.group(1)
            if any(email.endswith(s) for s in _SKIP_SUFFIXES):
                return email
            local, _, domain = email.partition('@')
            if is_pseudonym(email) or is_pseudonym(local):
                return email
            domain = domain.lower()
            # SUSE addresses are public: module authors, packagers, the
            # security team. The domain is not scrubbed either.
            if domain in _SAFE_DOMAINS or is_preserved_domain(domain):
                return email
            return self._get_fake_email(email)

        return EMAIL_RE.sub(lambda m: _replace(m), text)
