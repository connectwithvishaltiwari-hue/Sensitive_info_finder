# API (interactive docs at /docs)
| Method & path | Auth | Purpose |
|---|---|---|
| `GET /api/health` | - | liveness |
| `GET /api/entities` | - | entity catalogue: risk, support level, default action |
| `POST /api/scan` `{text, mode: rules|hybrid}` | - | detections (offsets), actions, policy decision, sanitized preview |
| `POST /api/scan-file` multipart `file`, `mode` | - | same for .txt .md .csv .log .json .pdf .docx (max 5 MB) |
| `POST /api/chat` `{prompt, mode, confirm_warnings, restore_placeholders}` | - | full gateway flow; returns `status`: `ok`, `blocked`, `needs_confirmation`, `response_blocked`, `provider_error` |
| `GET /api/settings` | - | current policy + provider name (never secrets) |
| `PUT /api/settings` | `X-API-Key` | update policy (validated) |
| `GET /api/admin/check` | `X-API-Key` | verify admin key |
| `GET /api/stats` | - | anonymous counts |
| `GET /api/evaluation` | - | latest evaluation summary or `{available:false}` |

Errors: 401 admin key missing/wrong, 413 too large, 415 unsupported file, 422 validation, 503 mode unavailable.
Client-supplied fields can never relax policy: `/api/chat` ignores everything except its four fields.
