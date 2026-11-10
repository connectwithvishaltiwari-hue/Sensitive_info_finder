from __future__ import annotations
import httpx
from .base import LLMProvider, ProviderError


class OpenAICompatibleProvider(LLMProvider):
    """Works with any server exposing POST {base_url}/chat/completions
    (OpenAI, Azure-compatible gateways, Groq, Together, Ollama, vLLM, ...).
    Credentials come from environment variables on the server only."""
    is_mock = False

    def __init__(self, base_url: str, api_key: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.name = f"openai-compatible:{model}"

    def complete(self, prompt: str, timeout: float) -> str:
        try:
            r = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=timeout)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"] or ""
        except httpx.TimeoutException:
            raise ProviderError("provider timed out") from None
        except Exception:
            # never include the exception text: it can echo request details
            raise ProviderError("provider request failed") from None


class BrokenProvider(LLMProvider):
    """Used when LLM_PROVIDER is set but misconfigured: fails safely at call time."""
    is_mock = False

    def __init__(self, reason: str):
        self.name = "unconfigured"
        self.reason = reason

    def complete(self, prompt: str, timeout: float) -> str:
        raise ProviderError(self.reason)


def build_provider() -> LLMProvider:
    import os
    from .mock import MockProvider
    kind = os.environ.get("LLM_PROVIDER", "mock").strip().lower()
    if kind == "mock":
        return MockProvider()
    if kind == "openai_compatible":
        key, url = os.environ.get("LLM_API_KEY"), os.environ.get("LLM_BASE_URL")
        model = os.environ.get("LLM_MODEL")
        if not (key and url and model):
            return BrokenProvider("LLM_API_KEY, LLM_BASE_URL and LLM_MODEL must all be set")
        return OpenAICompatibleProvider(url, key, model)
    return BrokenProvider(f"unknown LLM_PROVIDER '{kind}'")
