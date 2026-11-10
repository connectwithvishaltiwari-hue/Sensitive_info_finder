"""Central configuration and the entity catalogue."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent       # backend/
PROJECT_ROOT = BASE_DIR.parent                           # repo root
MAX_INPUT_CHARS = 100_000
MAX_FILE_BYTES = 5 * 1024 * 1024
CONTEXT_WINDOW = 40  # chars before a match searched for context words

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}

# entity -> (risk, support level, default policy action, description)
# support: reliable = format/checksum based; moderate = needs context words or
# heuristics; experimental = high false-positive/negative rate; statistical = ML model
ENTITY_CATALOG = {
    "PRIVATE_KEY":          (HIGH,   "reliable",     "BLOCK", "PEM private key block"),
    "API_KEY":              (HIGH,   "reliable",     "BLOCK", "Cloud/API keys (AWS, GitHub, Slack, Google, Stripe, sk-...) and key=value secrets"),
    "JWT_TOKEN":            (HIGH,   "reliable",     "BLOCK", "JSON Web Token"),
    "PASSWORD":             (HIGH,   "moderate",     "BLOCK", "Password-like value after 'password:' / 'pwd=' (heuristic)"),
    "DB_CONNECTION_STRING": (HIGH,   "reliable",     "BLOCK", "URL with embedded user:password"),
    "CREDIT_CARD":          (HIGH,   "reliable",     "MASK",  "Payment card number (Luhn-validated)"),
    "AADHAAR":              (HIGH,   "reliable",     "MASK",  "Aadhaar-like 12 digits (Verhoeff-validated)"),
    "BANK_ACCOUNT":         (HIGH,   "moderate",     "MASK",  "9-18 digit number after 'account no' (context required)"),
    "PASSPORT":             (HIGH,   "moderate",     "MASK",  "Indian passport format after 'passport' (context required)"),
    "PAN":                  (MEDIUM, "reliable",     "MASK",  "Indian PAN format (4th-letter category checked)"),
    "EMAIL_ADDRESS":        (MEDIUM, "reliable",     "MASK",  "Email address"),
    "PHONE_NUMBER":         (MEDIUM, "moderate",     "MASK",  "Phone number (Indian formats, +country code, or context word)"),
    "UPI_ID":               (MEDIUM, "moderate",     "MASK",  "UPI handle such as name@okaxis"),
    "DATE_OF_BIRTH":        (MEDIUM, "experimental", "MASK",  "Date after 'DOB' / 'born on'"),
    "CUSTOM_KEYWORD":       (MEDIUM, "reliable",     "MASK",  "Admin-configured confidential keywords"),
    "ADDRESS":              (MEDIUM, "experimental", "WARN",  "Text after 'address is' containing a digit"),
    "PERSON":               (LOW,    "statistical",  "MASK",  "Person name (spaCy NER; may miss or mislabel)"),
    "LOCATION":             (LOW,    "statistical",  "ALLOW", "Place name (spaCy NER; often harmless)"),
    "IP_ADDRESS":           (LOW,    "moderate",     "MASK",  "IPv4 address"),
    "IFSC":                 (LOW,    "moderate",     "ALLOW", "Bank branch code (public information)"),
}
RISK_BY_ENTITY = {k: v[0] for k, v in ENTITY_CATALOG.items()}
DEFAULT_ENTITY_ACTIONS = {k: v[2] for k, v in ENTITY_CATALOG.items()}


def risk_of(entity_type: str) -> str:
    return RISK_BY_ENTITY.get(entity_type, MEDIUM)


def max_risk(levels) -> str:
    levels = list(levels)
    return max(levels, key=_RANK.get) if levels else "NONE"


# ---- environment-driven settings (read at call time so tests can override) ----
def db_path() -> Path:
    default = PROJECT_ROOT / "data" / "app.db"
    # Vercel's filesystem is read-only except /tmp (data there is ephemeral;
    # set DATABASE_URL to use Supabase for persistence).
    if os.environ.get("VERCEL"):
        default = Path("/tmp/sid-app.db")
    return Path(os.environ.get("SID_DB_PATH", default))


def llm_timeout() -> float:
    try:
        return float(os.environ.get("LLM_TIMEOUT", "30"))
    except ValueError:
        return 30.0
