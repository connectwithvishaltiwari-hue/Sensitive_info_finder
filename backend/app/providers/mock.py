from .base import LLMProvider

LEAK_TRIGGER = "[[LEAK_TEST]]"


class MockProvider(LLMProvider):
    """Offline stand-in for a real LLM. Clearly labelled as a mock everywhere.
    If the prompt contains [[LEAK_TEST]] it deliberately returns fake secrets so
    you can demonstrate response scanning."""
    name = "mock-llm"
    is_mock = True

    def __init__(self, record: bool = False):
        self.record = record            # tests only: remember what was received
        self.received: list[str] = []

    def complete(self, prompt: str, timeout: float) -> str:
        if self.record:
            self.received.append(prompt)
        if LEAK_TRIGGER in prompt:
            return ("Sure! You can reach the admin at admin.demo@example.com and "
                    "use key AKIAIOSFODNN7EXAMPLE to log in.")
        return (f"[MOCK MODEL - not a real LLM] I received your prompt "
                f"({len(prompt)} characters). Echo of the first 200 characters: {prompt[:200]}")
