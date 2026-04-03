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
