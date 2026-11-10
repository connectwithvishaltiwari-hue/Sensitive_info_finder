from abc import ABC, abstractmethod


class ProviderError(Exception):
    """Raised by providers. Messages must NOT contain prompt text."""


class LLMProvider(ABC):
    name: str = "base"
    is_mock: bool = False

    @abstractmethod
    def complete(self, prompt: str, timeout: float) -> str:
        ...
