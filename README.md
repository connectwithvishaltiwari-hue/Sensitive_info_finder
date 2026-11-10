# Sensitive Information Detector - privacy layer for LLMs

Detects sensitive data in prompts and in model responses, applies a configurable policy
(ALLOW / WARN / MASK / BLOCK) on the **server**, and only ever sends sanitized text to the model.
All test data is synthetic. This tool reduces exposure; it cannot guarantee detection of every sensitive value.

## Features
* 20 entity types: PII, India IDs (Aadhaar, PAN, passport, IFSC, UPI), credentials (API keys, JWT, private keys, passwords, DB URLs), financial (cards, bank accounts), custom keywords, names/locations via spaCy.
* Rules / NLP-only / Hybrid detection modes; overlap-safe masking; Unicode safe.
* Policy engine with per-entity actions, confidence thresholds, admin-protected settings.
* LLM gateway: scan -> policy -> mask -> **verify (fail closed)** -> provider -> scan response -> output policy. Mock provider included; OpenAI-compatible adapter via env vars.
* Web UI: Text scanner (+ file upload), LLM playground, Analytics, Settings.
* SQLite stores settings and anonymous counts only (never prompts).
* Reproducible evaluation (dataset generator, strict/lenient P/R/F1, FPR, leakage, latency).
* 137+ pytest tests, Dockerfile, GitHub Actions CI.

## Setup (Windows PowerShell, Python 3.11/3.12)
    cd backend
    py -3.12 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    python -m spacy download en_core_web_sm

## Run the app
    python -m uvicorn app.main:app --reload
Open http://127.0.0.1:8000. Set `ADMIN_API_KEY` in your environment before deployment and use its value in the `X-API-Key` header for protected Settings endpoints. If it is not set locally, a random key is generated on each start, so Settings stay locked until you set one.

## Test
    python -m pytest -q          # from backend/
    python -m app.demo           # 20 synthetic cases

## Evaluation (from the project root)
    python evaluation/generate_dataset.py
    python evaluation/evaluate.py
Results go to `evaluation/results/` and appear in the Analytics page. Actual numbers: `docs/evaluation_results.md`.

## Optional: real LLM
Set `LLM_PROVIDER=openai_compatible`, `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` in `.env` on the server and restart.
Keys never reach the browser. Only sanitized prompts are sent.

## Docker
    copy .env.example .env
    docker compose up --build

## Docs
`docs/`: architecture, methodology, evaluation_results, limitations, api, demo_script, report_outline, viva_questions.


## Run backend tests on Windows

From PowerShell, open the `backend` directory and run `./setup_and_test.ps1`.
This creates and uses the backend-local `.venv`, installs all dependencies,
and runs tests with that environment's Python interpreter.


## Deploy on Vercel + Supabase
1. Supabase: Project Settings -> Database -> Connection string -> **Transaction pooler** (port 6543). URL-encode special characters in the password.
2. Vercel: import the repo (Root Directory = repo root) and add Environment Variables:
   `ADMIN_API_KEY` (long random secret), `DATABASE_URL` (Supabase pooler string), optionally `LLM_PROVIDER` etc.
3. Deploy. Check `https://<app>.vercel.app/api/health`, then `/api/stats`.
The Vercel build is rules-mode only (spaCy/Presidio exceed Vercel's 250 MB limit). For Hybrid mode use Docker (Render/Railway/Fly.io).
