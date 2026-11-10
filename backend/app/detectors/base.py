from abc import ABC, abstractmethod
from ..models import Finding


class Detector(ABC):
    name: str = "base"

    @abstractmethod
    def detect(self, text: str) -> list[Finding]:
        ...
