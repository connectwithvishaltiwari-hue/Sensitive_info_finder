import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import MAX_INPUT_CHARS

client = TestClient(app)


def test_index_page_served():
    r = client.get("/")
    assert r.status_code == 200 and "Sensitive Information Detector" in r.text


def test_scan_clean_text():
    r = client.post("/api/scan", json={"text": "Explain how gradient descent works."})
    assert r.status_code == 200
    j = r.json()
    assert j["has_sensitive"] is False and j["findings"] == []


def test_scan_finds_email_and_returns_offsets_not_values():
    text = "Mail priya.sharma@example.com now"
    j = client.post("/api/scan", json={"text": text}).json()
    assert j["has_sensitive"] is True
    f = j["findings"][0]
    assert f["entity_type"] == "EMAIL_ADDRESS"
    assert text[f["start"]:f["end"]] == "priya.sharma@example.com"
    assert "value" not in f
    assert "priya.sharma@example.com" not in j["sanitized_text"]


def test_oversized_rejected():
    r = client.post("/api/scan", json={"text": "a" * (MAX_INPUT_CHARS + 1)})
    assert r.status_code == 422


def test_malformed_requests_rejected():
    assert client.post("/api/scan", json={}).status_code == 422
    assert client.post("/api/scan", json={"text": 123}).status_code == 422
    assert client.post("/api/scan", json={"text": "x", "mode": "bogus"}).status_code == 422
    assert client.post("/api/scan", content="not json",
                       headers={"Content-Type": "application/json"}).status_code == 422


def test_hybrid_mode_or_clean_503():
    r = client.post("/api/scan", json={"text": "Ananya Iyer sent it.", "mode": "hybrid"})
    assert r.status_code in (200, 503)
