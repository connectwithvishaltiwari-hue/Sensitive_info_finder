"""FastAPI app. The backend is the enforcement point: the browser can only
ask; policy, masking and provider calls all happen here."""
from __future__ import annotations
import json
import secrets
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import (ENTITY_CATALOG, MAX_FILE_BYTES, MAX_INPUT_CHARS,
                     PROJECT_ROOT)
from .policies.engine import PolicySettings, evaluate
from .services import gateway
from .services.files import FileError, extract_text
from .services.runtime import ScannerUnavailable, rt

STATIC_DIR = Path(__file__).parent / "static"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"

@asynccontextmanager
async def lifespan(_app):
    yield


app = FastAPI(title="Sensitive Information Detector", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

_CSP = ("default-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'")


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        resp.headers["Content-Security-Policy"] = _CSP
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------- models ----------------
Mode = Literal["rules", "hybrid"]


Direction = Literal["input", "output"]


class ScanRequest(BaseModel):
    text: str = Field(..., max_length=MAX_INPUT_CHARS)
    mode: Mode = "rules"
    direction: Direction = "input"      # "output" = judge it as an LLM response


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_INPUT_CHARS)
    mode: Mode = "rules"
    confirm_warnings: bool = False
    restore_placeholders: bool = False


def require_admin(x_api_key: str | None = Header(default=None)):
    if not x_api_key or not secrets.compare_digest(x_api_key, rt.admin_key):
        raise HTTPException(status_code=401, detail="Admin API key required")


# ---------------- helpers ----------------
def _scan_payload(text: str, mode: str, source: str, output: bool = False) -> dict:
    try:
        scanner = rt.get_scanner(mode)
    except ScannerUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    res = scanner.scan(text)
    dec = evaluate(res.clusters, rt.policy, output=output)
    rt.store.log_scan(source, mode, dec.overall, dec.items)
    body = res.to_dict()
    body["direction"] = "output" if output else "input"
    for f, it in zip(body["findings"], dec.items):
        f["action"], f["reason"] = it["action"], it["reason"]
    body["policy"] = {"overall": dec.overall, "messages": dec.messages}
    # sanitized preview = what the MASK policy would send
    from .engine import apply_masking
    act = {id(c): a for c, a in zip(res.clusters, dec.cluster_actions)}
    body["sanitized_text"] = apply_masking(text, res.clusters, lambda c: act[id(c)] == "MASK")[0]
    body["has_sensitive"] = len(res.findings) > 0
    body["text_length"] = len(text)
    return body


# ---------------- routes ----------------
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/entities")
def entities():
    return [{"entity": k, "risk": v[0], "support": v[1],
             "default_action": v[2], "description": v[3]}
            for k, v in ENTITY_CATALOG.items()]


@app.post("/api/scan")
def scan(req: ScanRequest):
    out = req.direction == "output"
    return _scan_payload(req.text, req.mode, "scanner_response" if out else "scanner", out)


@app.post("/api/scan-file")
def scan_file(file: UploadFile = File(...), mode: Mode = Form("rules")):
    data = file.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail=f"File larger than {MAX_FILE_BYTES // 1024 // 1024} MB")
    try:
        text = extract_text(file.filename or "", data)
    except FileError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    if len(text) > MAX_INPUT_CHARS:
        raise HTTPException(status_code=413, detail=f"Extracted text exceeds {MAX_INPUT_CHARS} characters")
    body = _scan_payload(text, mode, "file")
    body["extracted_text"] = text
    body["filename"] = (file.filename or "")[:200]
    return body


@app.post("/api/chat")
def chat(req: ChatRequest):
    try:
        return gateway.run(rt, req.prompt, req.mode, req.confirm_warnings,
                           req.restore_placeholders)
    except ScannerUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/api/settings")
def get_settings():
    p = rt.provider
    return {"policy": rt.policy.model_dump(),
            "provider": {"name": p.name, "is_mock": p.is_mock},
            "provider_help": ("Set LLM_PROVIDER=openai_compatible, LLM_API_KEY, "
                              "LLM_BASE_URL and LLM_MODEL in the server's .env file, "
                              "then restart. Keys are never sent to the browser.")}


@app.put("/api/settings")
def put_settings(policy: PolicySettings, x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    rt.set_policy(policy)
    return {"policy": rt.policy.model_dump()}


@app.get("/api/admin/check")
def admin_check(x_api_key: str | None = Header(default=None)):
    require_admin(x_api_key)
    return {"ok": True}


@app.get("/api/stats")
def stats():
    return rt.store.stats()


@app.get("/api/evaluation")
def evaluation():
    f = RESULTS_DIR / "summary.json"
    if not f.exists():
        return {"available": False}
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {"available": False}
    data["available"] = True
    return data
