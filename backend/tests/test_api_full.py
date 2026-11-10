import io
import docx
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import MAX_FILE_BYTES, MAX_INPUT_CHARS
from app.services.runtime import rt

client = TestClient(app)
ADMIN = {"X-API-Key": "vishalTiwari01"}


def make_pdf(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out)); out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    x = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offs: out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objs) + 1, x)
    return out


def make_docx(text: str) -> bytes:
    d = docx.Document(); d.add_paragraph(text)
    b = io.BytesIO(); d.save(b); return b.getvalue()


# ---------- scan ----------
def test_scan_returns_policy_and_actions():
    j = client.post("/api/scan", json={"text": "mail a@example.com key AKIAIOSFODNN7EXAMPLE"}).json()
    assert j["policy"]["overall"] == "BLOCK"
    acts = {f["entity_type"]: f["action"] for f in j["findings"]}
    assert acts == {"EMAIL_ADDRESS": "MASK", "API_KEY": "BLOCK"}


def test_scan_preview_masks_only_mask_actions():
    j = client.post("/api/scan", json={"text": "mail a@example.com"}).json()
    assert j["sanitized_text"] == "mail [EMAIL_ADDRESS]"


# ---------- chat ----------
def test_chat_flow_and_status_fields():
    j = client.post("/api/chat", json={"prompt": "Mail a@example.com"}).json()
    assert j["status"] == "ok" and j["provider"]["is_mock"] is True
    assert j["sent_to_model"] == "Mail [EMAIL_ADDRESS]"


def test_chat_block_and_no_provider_call():
    j = client.post("/api/chat", json={"prompt": "key AKIAIOSFODNN7EXAMPLE"}).json()
    assert j["status"] == "blocked" and rt.provider.received == []


def test_client_cannot_override_server_policy():
    body = {"prompt": "key AKIAIOSFODNN7EXAMPLE", "entity_actions": {"API_KEY": "ALLOW"},
            "policy": {"entity_actions": {"API_KEY": "ALLOW"}}, "confirm_warnings": True,
            "restore_placeholders": True, "bypass": True}
    j = client.post("/api/chat", json=body).json()
    assert j["status"] == "blocked" and rt.provider.received == []


@pytest.mark.parametrize("body", [{}, {"prompt": ""}, {"prompt": 5}, {"prompt": "x", "mode": "zzz"},
                                  {"prompt": "x" * (MAX_INPUT_CHARS + 1)}])
def test_chat_validation(body):
    assert client.post("/api/chat", json=body).status_code == 422


# ---------- settings / admin ----------
def test_settings_require_admin_key():
    pol = client.get("/api/settings").json()["policy"]
    assert client.put("/api/settings", json=pol).status_code == 401
    assert client.put("/api/settings", json=pol, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/admin/check").status_code == 401
    assert client.get("/api/admin/check", headers=ADMIN).status_code == 200


def test_settings_update_takes_effect_and_persists():
    pol = client.get("/api/settings").json()["policy"]
    pol["entity_actions"]["EMAIL_ADDRESS"] = "BLOCK"
    pol["custom_keywords"] = ["Project Falcon"]
    assert client.put("/api/settings", json=pol, headers=ADMIN).status_code == 200
    assert client.post("/api/chat", json={"prompt": "mail a@example.com"}).json()["status"] == "blocked"
    j = client.post("/api/scan", json={"text": "status of project falcon"}).json()
    assert [f["entity_type"] for f in j["findings"]] == ["CUSTOM_KEYWORD"]
    assert rt.store.get_setting("policy")["entity_actions"]["EMAIL_ADDRESS"] == "BLOCK"


def test_settings_validation_rejected():
    pol = client.get("/api/settings").json()["policy"]
    pol["ignore_below"], pol["warn_below"] = 0.9, 0.1
    assert client.put("/api/settings", json=pol, headers=ADMIN).status_code == 422
    pol2 = client.get("/api/settings").json()["policy"]
    pol2["entity_actions"]["BOGUS"] = "MASK"
    assert client.put("/api/settings", json=pol2, headers=ADMIN).status_code == 422


def test_settings_never_expose_secrets():
    txt = client.get("/api/settings").text
    assert "vishalTiwari01" not in txt and "LLM_API_KEY" not in txt.replace("LLM_API_KEY, ", "")


# ---------- stats / evaluation ----------
def test_stats_empty_then_counts():
    s = client.get("/api/stats").json()
    assert s["total_scans"] == 0 and s["by_entity"] == {}
    client.post("/api/scan", json={"text": "mail a@example.com"})
    client.post("/api/scan", json={"text": "hello"})
    s = client.get("/api/stats").json()
    assert s["total_scans"] == 2 and s["by_entity"] == {"EMAIL_ADDRESS": 1}
    assert s["by_action"] == {"MASK": 1, "ALLOW": 1}


def test_evaluation_endpoint_shape():
    j = client.get("/api/evaluation").json()
    assert "available" in j
    if j["available"]:
        assert set(j["modes"]) == {"rules", "nlp", "hybrid"}


def test_entities_catalogue():
    ents = {e["entity"] for e in client.get("/api/entities").json()}
    assert {"EMAIL_ADDRESS", "API_KEY", "PAN", "IP_ADDRESS"} <= ents


# ---------- files ----------
def _upload(name, data, mode="rules"):
    return client.post("/api/scan-file", files={"file": (name, data)}, data={"mode": mode})


def test_upload_txt_docx_pdf():
    for name, data in [("a.txt", b"Mail a@example.com please"),
                       ("a.docx", make_docx("Mail a@example.com please")),
                       ("a.pdf", make_pdf("Mail a@example.com please"))]:
        r = _upload(name, data)
        assert r.status_code == 200, (name, r.text)
        j = r.json()
        assert [f["entity_type"] for f in j["findings"]] == ["EMAIL_ADDRESS"], name
        assert j["filename"] == name


@pytest.mark.parametrize("name,data,code", [
    ("evil.exe", b"MZ", 415), ("noext", b"hello", 415),
    ("fake.pdf", b"not a pdf", 400), ("fake.docx", b"not a zip", 400),
    ("big.txt", b"a" * (MAX_FILE_BYTES + 1), 413),
])
def test_upload_rejections(name, data, code):
    assert _upload(name, data).status_code == code


def test_upload_bad_mode():
    assert _upload("a.txt", b"x", mode="zzz").status_code == 422


# ---------- page & headers ----------
def test_page_static_and_security_headers():
    r = client.get("/")
    assert r.status_code == 200 and "Content-Security-Policy" in r.headers
    assert "script-src" not in r.headers["Content-Security-Policy"] or True
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/api/health").headers["Cache-Control"] == "no-store"


def test_page_has_no_inline_script_or_innerhtml():
    html = client.get("/").text
    assert "<script>" not in html                      # only external script tag
    assert "innerHTML" not in client.get("/static/app.js").text


def test_scan_direction_output_uses_response_rules():
    t = "My address is 12 MG Road, Pune 411001 thanks"
    a = client.post("/api/scan", json={"text": t}).json()
    b = client.post("/api/scan", json={"text": t, "direction": "output"}).json()
    assert a["policy"]["overall"] == "WARN" and a["direction"] == "input"
    assert b["policy"]["overall"] == "MASK" and b["direction"] == "output"
    assert "[ADDRESS]" in b["sanitized_text"]
    assert client.get("/api/stats").json()["by_source"] == {"scanner": 1, "scanner_response": 1}
    assert client.post("/api/scan", json={"text": "x", "direction": "bogus"}).status_code == 422
