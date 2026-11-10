import sqlite3
import pytest
from app.providers.base import ProviderError
from app.providers.mock import MockProvider
from app.policies.engine import PolicySettings
from app.services import gateway

SECRET = "key AKIAIOSFODNN7EXAMPLE"


class Boom(MockProvider):
    def __init__(self, exc):
        super().__init__(record=True)
        self.exc = exc

    def complete(self, prompt, timeout):
        self.received.append(prompt)
        raise self.exc


def test_blocked_prompt_never_reaches_provider(_fresh_runtime):
    rt = _fresh_runtime
    r = gateway.run(rt, f"please use {SECRET} to deploy")
    assert r["status"] == "blocked" and r["provider_called"] is False
    assert rt.provider.received == []


def test_masked_prompt_reaches_provider_sanitised(_fresh_runtime):
    rt = _fresh_runtime
    r = gateway.run(rt, "Mail priya.sharma@example.com about the invoice")
    assert r["status"] == "ok" and r["input_modified"] is True
    assert rt.provider.received == ["Mail [EMAIL_ADDRESS] about the invoice"]
    assert "priya.sharma@example.com" not in r["response"]


def test_benign_prompt_passes_unchanged(_fresh_runtime):
    rt = _fresh_runtime
    r = gateway.run(rt, "Explain gradient descent")
    assert r["status"] == "ok" and not r["input_modified"]
    assert rt.provider.received == ["Explain gradient descent"]


def test_original_value_never_in_any_provider_call(_fresh_runtime):
    rt = _fresh_runtime
    prompts = ["a@example.com and PAN ABCPE1234F", "card 4111 1111 1111 1111 ok",
               "call +91 98765 43210"]
    for p in prompts:
        gateway.run(rt, p)
    blob = " ".join(rt.provider.received)
    for secret in ("a@example.com", "ABCPE1234F", "4111 1111 1111 1111", "98765 43210"):
        assert secret not in blob


def test_warn_requires_confirmation(_fresh_runtime):
    rt = _fresh_runtime
    p = "My address is 12 MG Road, Pune 411001 please format it"
    r = gateway.run(rt, p)
    assert r["status"] == "needs_confirmation" and rt.provider.received == []
    r2 = gateway.run(rt, p, confirm_warnings=True)
    assert r2["status"] == "ok" and len(rt.provider.received) == 1


def test_confirmation_cannot_unblock(_fresh_runtime):
    rt = _fresh_runtime
    r = gateway.run(rt, SECRET, confirm_warnings=True, restore=True)
    assert r["status"] == "blocked" and rt.provider.received == []


def test_response_with_secret_is_withheld(_fresh_runtime):
    rt = _fresh_runtime
    r = gateway.run(rt, "hello [[LEAK_TEST]]")
    assert r["status"] == "response_blocked" and r["response"] is None


def test_response_pii_is_masked(_fresh_runtime):
    rt = _fresh_runtime
    pol = PolicySettings()
    pol.entity_actions["API_KEY"] = "MASK"
    rt.set_policy(pol)
    r = gateway.run(rt, "hello [[LEAK_TEST]]")
    assert r["status"] == "ok" and r["output_modified"] is True
    assert "AKIAIOSFODNN7EXAMPLE" not in r["response"]
    assert "admin.demo@example.com" not in r["response"]


@pytest.mark.parametrize("exc", [ProviderError("provider timed out"), RuntimeError("secret internals")])
def test_provider_failures_handled_safely(_fresh_runtime, exc):
    rt = _fresh_runtime
    rt.provider = Boom(exc)
    r = gateway.run(rt, "Mail a@example.com")
    assert r["status"] == "provider_error" and r["response"] is None
    assert "secret internals" not in r["message"]
    assert "a@example.com" not in r["message"]


def test_fail_closed_if_sanitisation_breaks(_fresh_runtime, monkeypatch):
    rt = _fresh_runtime
    monkeypatch.setattr(gateway, "apply_masking", lambda text, *a, **k: (text, {}))
    r = gateway.run(rt, "Mail a@example.com")
    assert r["status"] == "blocked" and rt.provider.received == []


def test_restoration_is_opt_in_and_limited(_fresh_runtime):
    rt = _fresh_runtime
    # default: flag off -> no numbering, no restoration
    r = gateway.run(rt, "Mail priya@example.com now", restore=True)
    assert rt.provider.received[-1] == "Mail [EMAIL_ADDRESS] now"
    # admin enables: PII restored
    pol = PolicySettings(allow_placeholder_restoration=True)
    rt.set_policy(pol)
    r = gateway.run(rt, "Mail priya@example.com now", restore=True)
    assert rt.provider.received[-1] == "Mail [EMAIL_ADDRESS_1] now"
    assert "priya@example.com" in r["response"]
    # credentials are NEVER restored even when policy masks them
    pol.entity_actions["API_KEY"] = "MASK"
    rt.set_policy(pol)
    r = gateway.run(rt, SECRET, restore=True)
    assert r["status"] == "ok" and "AKIAIOSFODNN7EXAMPLE" not in r["response"]


def test_nothing_sensitive_persisted(_fresh_runtime):
    rt = _fresh_runtime
    unique = "uniq.marker.value@example.com"
    gateway.run(rt, f"mail {unique}")
    gateway.run(rt, "hello [[LEAK_TEST]]")
    dump = "\n".join(rt.store._db.iterdump())
    assert unique not in dump and "AKIAIOSFODNN7EXAMPLE" not in dump
    assert "mail" not in dump.replace("EMAIL", "")   # no prompt text either


def test_hybrid_unavailable_is_clean(_fresh_runtime):
    # hybrid either works or raises ScannerUnavailable, never a raw crash
    from app.services.runtime import ScannerUnavailable
    try:
        r = gateway.run(_fresh_runtime, "Ananya Iyer sent it", mode="hybrid")
        assert r["status"] in ("ok", "blocked", "needs_confirmation")
    except ScannerUnavailable:
        pass
