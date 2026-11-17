import re

from abc import ABC, abstractmethod


class Scrubber(ABC):
    name: str = ''
    skip_files: frozenset = frozenset()

    @abstractmethod
    def scrub(self, text: str) -> str:
        ...

    @property
    @abstractmethod
    def mapping(self) -> dict:
        ...


# Every pseudonym a scrubber hands out, old forms and new (pipeline._FORMS):
# a value matching this is already scrubbed and must not be scrubbed again,
# nor reported by verify as a leak.
PSEUDONYM_RE = re.compile(
    r'(?:hostname_\d+|host-\d+|user_\d+|user\d+|domain_\d+|dom\d+|sub_\d+'
    r'|keyword_\d+|cn_(?:\d+|[0-9a-f]{12})|ou_(?:\d+|[0-9a-f]{12})'
    r'|email_(?:\d+|[0-9a-f]{12})@scrubbed\.local'
    r'|scrubbed_pass_(?:\d+|[0-9a-f]{12})|SCRUBBED_[A-Z]+_(?:\d+|[0-9a-f]{12})'
    r'|SERIAL_\d+)'
    r'(?:\.[A-Za-z0-9_-]+)*',
    re.IGNORECASE,
)


def is_pseudonym(value: str) -> bool:
    return PSEUDONYM_RE.fullmatch(value) is not None
