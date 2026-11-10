"""Synthetic, reproducible dataset with exact span annotations.

Every value is fictional/randomly generated. Spans are half-open character
offsets (text[start:end]) in Python code points. Labeled slots look like
{EMAIL_ADDRESS}; unlabeled look-alike values (hard negatives) use {~NAME}.
"""
from __future__ import annotations
import json
import random
import re
import string
from pathlib import Path

from ..detectors.validators import verhoeff_check_digit

LABELS = ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "AADHAAR", "PAN", "CREDIT_CARD",
          "API_KEY", "PASSWORD", "PRIVATE_KEY", "DB_CONNECTION_STRING",
          "IP_ADDRESS", "UPI_ID", "IFSC"]

FIRST = ["Ananya", "Rohan", "Meera", "Karan", "Divya", "Arjun", "Sneha", "Vikram", "Neha",
         "Aditya", "Pooja", "Rahul", "Isha", "Manish", "Kavya", "Sanjay", "Tanvi", "Nikhil"]
LAST = ["Iyer", "Sharma", "Patel", "Nair", "Gupta", "Reddy", "Mehta", "Kapoor", "Joshi",
        "Singh", "Verma", "Menon", "Bose", "Desai", "Rao", "Chopra"]
DOMAINS = ["example.com", "example.org", "mail.example.in", "corp.example.net"]
UPI_HANDLES = ["okaxis", "ybl", "paytm", "oksbi", "okicici"]
UP, LO, DG = string.ascii_uppercase, string.ascii_lowercase, string.digits
ALNUM = UP + LO + DG


def _luhn_complete(prefix: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return prefix + str((10 - total % 10) % 10)


def _name(r):  return f"{r.choice(FIRST)} {r.choice(LAST)}"


def g_EMAIL_ADDRESS(r):
    f, l = r.choice(FIRST).lower(), r.choice(LAST).lower()
    style = r.choice(["{f}.{l}", "{f}_{l}", "{f}{l}{n}", "{f}.{l}+work"])
    return style.format(f=f, l=l, n=r.randint(1, 99)) + "@" + r.choice(DOMAINS)


def g_PHONE_NUMBER(r):
    d = r.choice("6789") + "".join(r.choice(DG) for _ in range(9))
    return r.choice([f"+91 {d[:5]} {d[5:]}", f"{d[:5]}-{d[5:]}", d, f"+91{d}", f"{d[:5]} {d[5:]}"])


def g_AADHAAR(r):
    base = r.choice("23456789") + "".join(r.choice(DG) for _ in range(10))
    n = base + str(verhoeff_check_digit(base))
    return r.choice([f"{n[:4]} {n[4:8]} {n[8:]}", n, f"{n[:4]}-{n[4:8]}-{n[8:]}"])


def g_PAN(r):
    return "".join(r.choice(UP) for _ in range(3)) + r.choice("ABCFGHLJPT") + r.choice(UP) + \
           "".join(r.choice(DG) for _ in range(4)) + r.choice(UP)


def g_CREDIT_CARD(r):
    n = _luhn_complete(r.choice(["4", "5"]) + "".join(r.choice(DG) for _ in range(14)))
    return r.choice([" ".join(n[i:i+4] for i in range(0, 16, 4)),
                     "-".join(n[i:i+4] for i in range(0, 16, 4)), n])


def g_API_KEY(r):
    kind = r.choice(["aws", "gh", "stripe", "google", "sk"])
    if kind == "aws":    return "AKIA" + "".join(r.choice(UP + DG) for _ in range(16))
    if kind == "gh":     return "ghp_" + "".join(r.choice(ALNUM) for _ in range(36))
    if kind == "stripe": return "sk_live_" + "".join(r.choice(ALNUM) for _ in range(24))
    if kind == "google": return "AIza" + "".join(r.choice(ALNUM + "_-") for _ in range(35))
    return "sk-" + "".join(r.choice(ALNUM) for _ in range(32))


def g_PASSWORD(r):
    core = "".join(r.choice(LO + UP) for _ in range(r.randint(5, 8)))
    return core + r.choice("!@#$%&") + "".join(r.choice(DG) for _ in range(r.randint(2, 3)))


def g_PRIVATE_KEY(r):
    body = "".join(r.choice(ALNUM + "+/") for _ in range(60))
    return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"


def g_DB_CONNECTION_STRING(r):
    scheme = r.choice(["postgresql", "mysql", "mongodb"])
    pw = "".join(r.choice(ALNUM) for _ in range(10))
    return f"{scheme}://{r.choice(['appuser', 'svc_api', 'admin'])}:{pw}@db{r.randint(1,9)}.internal.example.com:5432/orders"


def g_PERSON(r):         return _name(r)
def g_IP_ADDRESS(r):     return r.choice([f"10.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}",
                                          f"192.168.{r.randint(0,255)}.{r.randint(1,254)}",
                                          f"172.16.{r.randint(0,255)}.{r.randint(1,254)}"])
def g_UPI_ID(r):         return f"{r.choice(FIRST).lower()}{r.randint(1,99)}@{r.choice(UPI_HANDLES)}"
def g_IFSC(r):           return r.choice(["HDFC", "ICIC", "SBIN", "UTIB"]) + "0" + "".join(r.choice(DG) for _ in range(6))

# ---- unlabeled look-alikes (hard negatives) ----
def n_AADHAAR_BAD(r):
    while True:
        base = r.choice("23456789") + "".join(r.choice(DG) for _ in range(10))
        d = (verhoeff_check_digit(base) + r.randint(1, 9)) % 10
        if d != verhoeff_check_digit(base):
            n = base + str(d); return f"{n[:4]} {n[4:8]} {n[8:]}"
def n_CARD_BAD(r):
    n = _luhn_complete("4" + "".join(r.choice(DG) for _ in range(14)))
    n = n[:-1] + str((int(n[-1]) + r.randint(1, 9)) % 10)
    return " ".join(n[i:i+4] for i in range(0, 16, 4))
def n_PAN_BAD(r):
    return "".join(r.choice(UP) for _ in range(3)) + r.choice("DEIKMNOQRSUVWXYZ") + r.choice(UP) + \
           "".join(r.choice(DG) for _ in range(4)) + r.choice(UP)
def n_ORDER(r):          return r.choice("12345") + "".join(r.choice(DG) for _ in range(9))
def n_VERSION(r):        return f"v{r.randint(1,9)}.{r.randint(0,20)}.{r.randint(0,30)}"
def n_VERSION4(r):       return f"v{r.randint(1,9)}.{r.randint(0,9)}.{r.randint(0,9)}.{r.randint(0,9)}"
def n_BADIP(r):          return f"{r.randint(256,999)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}"
def n_HASH(r):           return "".join(r.choice("0123456789abcdef") for _ in range(40))
def n_ZIPLIKE(r):        return "".join(r.choice(DG) for _ in range(6))
def n_PLACEHOLDER(r):    return r.choice(["YOUR_API_KEY_HERE", "<your-api-key>", "changeme-placeholder-key"])

GEN = {k[2:]: v for k, v in globals().items() if k.startswith("g_")}
GEN.update({"~" + k[2:]: v for k, v in globals().items() if k.startswith("n_")})

# ---------------- templates ----------------
POSITIVE = {
 "prompt": [
  "Please draft a polite reply to {EMAIL_ADDRESS} about the delayed shipment.",
  "Summarise this note: {PERSON} said the invoice should go to {EMAIL_ADDRESS}.",
  "My phone number is {PHONE_NUMBER}, can you format it for a form?",
  "My PAN is {PAN}; explain how to link it with Aadhaar.",
  "Help me understand why my Aadhaar {AADHAAR} was rejected on the portal.",
  "Is it safe to share my credit card {CREDIT_CARD} on this website?",
  "Reach {PERSON} at {PHONE_NUMBER} or {EMAIL_ADDRESS} and confirm the meeting.",
  "Write a short bio for {PERSON}, who joined the analytics team last month.",
  "Customer {PERSON} paid via UPI {UPI_ID}, please create a receipt.",
  "The bank branch IFSC {IFSC} is on the cheque, what does each part mean?",
  "Why can't I ping the server at ip {IP_ADDRESS} from my laptop?",
  "mera phone number {PHONE_NUMBER} hai, isse kaise format karun?",
  "mera email {EMAIL_ADDRESS} hai, ek reply likh do.",
 ],
 "email": [
  "Hi {PERSON},\n\nPlease find the invoice attached. Call me on {PHONE_NUMBER} if needed.\n\nRegards,\n{PERSON}",
  "Subject: Account update\n\nDear {PERSON}, your registered email {EMAIL_ADDRESS} has been verified.",
  "Forwarding KYC details: PAN {PAN}, Aadhaar {AADHAAR}. Please do not share further.",
  "Payment reminder for {PERSON}. Pay to {UPI_ID} before Friday.",
 ],
 "support": [
  "Agent: Can you confirm your email?\nCustomer: Sure, it's {EMAIL_ADDRESS}.",
  "Customer {PERSON} reports login failure. Contact: {PHONE_NUMBER}. Escalate if unresolved.",
  "Agent: What card was charged?\nCustomer: {CREDIT_CARD}, expiring next year.",
  "Ticket 4821 - user says password: {PASSWORD} no longer works after reset.",
  "Customer {PERSON} (email {EMAIL_ADDRESS}) asks to update the account.",
 ],
 "code": [
  "export AWS_ACCESS_KEY_ID={API_KEY}\nexport AWS_REGION=ap-south-1",
  "api_key = \"{API_KEY}\"\nclient = Client(api_key)",
  "DATABASE_URL={DB_CONNECTION_STRING}\nDEBUG=false",
  "conn = connect(\"{DB_CONNECTION_STRING}\")\ncur = conn.cursor()",
  "# TODO remove before commit\nadmin password: {PASSWORD}\nhost: {IP_ADDRESS}",
  "{PRIVATE_KEY}",
  "const token = process.env.TOKEN || \"{API_KEY}\";",
  "ssh deploy@{IP_ADDRESS} -p 22",
 ],
 "response": [
  "Sure! I have sent the message to {EMAIL_ADDRESS} as requested.",
  "You can contact {PERSON} on {PHONE_NUMBER} for the details.",
  "Here is the config you asked for:\nDATABASE_URL={DB_CONNECTION_STRING}",
  "The key {API_KEY} should be rotated immediately.",
  "I've saved the card {CREDIT_CARD} to your profile.",
 ],
}
NEGATIVE = [
 "Explain how gradient descent works.", "What is the difference between a list and a tuple in Python?",
 "Write a haiku about monsoon rain.", "Summarise the causes of the French Revolution in five bullets.",
 "How do I reverse a linked list in C++?", "Give me a study plan for the GATE exam.",
 "Translate 'good morning' into Hindi, Tamil and Bengali.", "Explain the CAP theorem with an example.",
 "What are the pros and cons of microservices?", "Suggest names for a college tech fest.",
 "Draft an agenda for a 30 minute team standup.", "How does public key cryptography work?",
 "Compare REST and GraphQL for a small startup.", "Help me write a cover letter for a data analyst role.",
 "Sure! Here is a simple explanation of neural networks in plain language.",
 "I can help with that. Could you share more details about the problem you are facing?",
 "The meeting is scheduled for next Tuesday at 3 pm in the main conference room.",
 "def add(a, b):\n    return a + b\n\nprint(add(2, 3))",
 "SELECT name, COUNT(*) FROM orders GROUP BY name ORDER BY 2 DESC;",
 "Password is required for login. Please choose a strong one.",
 "Set api_key = YOUR_API_KEY_HERE in the config file before running.",
 "The email address field must contain an @ symbol.",
 "Remember to never commit secrets or private keys to git.",
 "What is the capital of Australia and when was it founded?",
 "Explain what a credit card Luhn checksum is, without using real numbers.",
]
HARD_NEG = [
 "Reference id {~AADHAAR_BAD} was logged by the audit system.",
 "Order code {~CARD_BAD} shipped yesterday.",
 "Part number {~PAN_BAD} is in stock at the warehouse.",
 "Order number {~ORDER} was delivered on time.",
 "Upgrade to {~VERSION} to fix the memory leak.",
 "Latest firmware is {~VERSION4}, released last week.",
 "The address {~BADIP} is not a valid IPv4 address.",
 "Commit {~HASH} fixed the failing test.",
 "Pincode {~ZIPLIKE} covers the central district.",
 "Set api_key = {~PLACEHOLDER} in your .env file.",
 "Password is required for {~VERSION} of the portal.",
 "The ticket id is {~ORDER}; please quote it in all replies.",
 "Use the format ABCDE1234F only as a documentation example, it is not a valid PAN.",
]
_SLOT = re.compile(r"\{(~?)([A-Z_0-9]+)\}")


def fill(template: str, rng: random.Random) -> tuple[str, list[dict]]:
    out, ents, pos = [], [], 0
    for m in _SLOT.finditer(template):
        out.append(template[pos:m.start()])
        start = sum(len(x) for x in out)
        value = GEN[m.group(1) + m.group(2)](rng)
        out.append(value)
        if not m.group(1):
            ents.append({"label": m.group(2), "start": start, "end": start + len(value)})
        pos = m.end()
    out.append(template[pos:])
    return "".join(out), ents


def generate(seed: int = 42, positives_per_template: int = 4,
             hard_neg_per_template: int = 3) -> list[dict]:
    rng = random.Random(seed)
    docs: list[dict] = []
    n = 0

    def add(kind, source, text, ents):
        nonlocal n
        n += 1
        docs.append({"id": f"d{n:04d}", "kind": kind, "source": source,
                     "text": text, "entities": ents})

    for source, templates in POSITIVE.items():
        for t in templates:
            for _ in range(positives_per_template):
                add("positive", source, *fill(t, rng))
    for t in NEGATIVE:
        add("negative", "prompt", t, [])
    for t in HARD_NEG:
        for _ in range(hard_neg_per_template):
            add("hard_negative", "prompt", *fill(t, rng))
    # multi-entity documents
    multi = ["Contact {PERSON} ({EMAIL_ADDRESS}, {PHONE_NUMBER}) about PAN {PAN}.",
             "Card {CREDIT_CARD} and UPI {UPI_ID} were used by {PERSON}.",
             "Config:\napi_key = {API_KEY}\nDATABASE_URL={DB_CONNECTION_STRING}\nhost {IP_ADDRESS}"]
    for t in multi:
        for _ in range(5):
            add("positive", "prompt", *fill(t, rng))
    for d in docs:
        d["entities"].sort(key=lambda e: e["start"])
    return docs


def validate(docs: list[dict]) -> None:
    for d in docs:
        for e in d["entities"]:
            assert 0 <= e["start"] < e["end"] <= len(d["text"]), d["id"]
            assert e["label"] in LABELS, e["label"]


def save(docs: list[dict], root: Path) -> tuple[Path, Path]:
    (root / "synthetic").mkdir(parents=True, exist_ok=True)
    (root / "annotations").mkdir(parents=True, exist_ok=True)
    tp, ap = root / "synthetic" / "texts.jsonl", root / "annotations" / "spans.jsonl"
    with tp.open("w", encoding="utf-8") as ft, ap.open("w", encoding="utf-8") as fa:
        for d in docs:
            ft.write(json.dumps({k: d[k] for k in ("id", "kind", "source", "text")}, ensure_ascii=False) + "\n")
            fa.write(json.dumps({"id": d["id"], "entities": d["entities"]}) + "\n")
    return tp, ap


def load(root: Path) -> list[dict]:
    texts = [json.loads(l) for l in (root / "synthetic" / "texts.jsonl").read_text(encoding="utf-8").splitlines() if l]
    spans = {j["id"]: j["entities"] for j in
             (json.loads(l) for l in (root / "annotations" / "spans.jsonl").read_text(encoding="utf-8").splitlines() if l)}
    for t in texts:
        t["entities"] = spans[t["id"]]
    return texts
