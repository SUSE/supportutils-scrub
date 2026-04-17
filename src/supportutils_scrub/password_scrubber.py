# password_scrubber.py
import re
from supportutils_scrub.scrubber import Scrubber

_PASSWORD_RE = re.compile(
    r'(?i)(\b(?:password|passwd)\s*[:=]\s*["\']?)'
    r'(?!\*REMOVED)'
    r'(?!scrubbed_pass_)'
    r'([A-Za-z0-9+/]{8,})'
)


class PasswordScrubber(Scrubber):
    name = 'password'
    """Finds and replaces password values """

    def __init__(self, mappings=None):
        self.password_dict = dict(mappings.get('password', {})) if mappings else {}
        self._counter = len(self.password_dict)

    @property
    def mapping(self):
        return self.password_dict

    def _get_fake_password(self, real_value):
        """Returns fake password for a real one."""
        if real_value in self.password_dict:
            return self.password_dict[real_value]
        self._counter += 1
        fake = f"scrubbed_pass_{self._counter}"
        self.password_dict[real_value] = fake
        return fake

    def scrub(self, text):
        """Replaces password values in text. Returns scrubbed text."""
        def _replace(m):
            prefix = m.group(1)   
            value = m.group(2)    
            return prefix + self._get_fake_password(value)

        return _PASSWORD_RE.sub(_replace, text)
