from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..config import CONTEXT_WINDOW
from ..models import Finding
from .base import Detector
from .validators import (luhn_valid, verhoeff_valid, not_placeholder,
                         password_like, digits_only, valid_ipv4,
                         has_digit, ifsc_ok)


@dataclass(frozen=True)
class Rule:
    name: str
    entity: str
    pattern: re.Pattern
    score: float
    group: int = 0                       # which regex group is the sensitive span
    validator: Optional[Callable[[str], bool]] = None
    context: tuple = ()                  # words that raise confidence if nearby
    boosted_score: float = 0.0


def _c(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


# NOTE: [0-9] is used instead of \d so only ASCII digits match.
RULES: tuple[Rule, ...] = (
    Rule("email", "EMAIL_ADDRESS",
         _c(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])"),
         0.90),
    Rule("phone_in", "PHONE_NUMBER",
         _c(r"(?<![0-9+])(?:\+91[\s-]?)?[6-9][0-9]{4}[\s-]?[0-9]{5}(?![0-9])"),
         0.60, context=("phone", "mobile", "call", "contact", "whatsapp", "mob",
                  "फोन", "मोबाइल", "नंबर"),
         boosted_score=0.85),
    Rule("phone_intl", "PHONE_NUMBER",
         _c(r"(?<![0-9+])\+[0-9]{1,3}[\s-]?\(?[0-9]{2,4}\)?[\s-]?[0-9]{3,4}[\s-]?[0-9]{3,4}(?![0-9])"),
         0.60, context=("phone", "mobile", "call", "contact", "whatsapp"),
         boosted_score=0.85),
    Rule("phone_ctx", "PHONE_NUMBER",
         _c(r"\b(?:phone|telephone|mobile|mob|cell|contact|whatsapp|tel)\b"
            r"(?:\s+(?:number|no\.?|num|#))?\s*(?:is|[:=-])?\s*"
            r"(\+?[0-9][0-9 ().-]{6,18}[0-9])", re.I),
         0.80, group=1, validator=lambda v: 8 <= len(digits_only(v)) <= 15),
    Rule("aadhaar", "AADHAAR",
         _c(r"(?<![0-9])(?<![0-9][ -])[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}(?![0-9])(?![ -][0-9])"),
         0.75, validator=verhoeff_valid,
         context=("aadhaar", "aadhar", "uidai", "uid"), boosted_score=0.95),
    Rule("pan", "PAN",
         _c(r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z](?![A-Za-z0-9])"),
         0.80, context=("pan", "permanent account", "income tax"),
         boosted_score=0.95),
    Rule("credit_card", "CREDIT_CARD",
         _c(r"(?<![0-9-])(?:[0-9][ -]?){12,18}[0-9](?![0-9-])"),
         0.85, validator=luhn_valid,
         context=("card", "visa", "mastercard", "credit", "debit", "cvv"),
         boosted_score=0.95),
    Rule("aws_key", "API_KEY",
         _c(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), 0.95),
    Rule("github_token", "API_KEY",
         _c(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), 0.95),
    Rule("slack_token", "API_KEY",
         _c(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0.90),
    Rule("sk_style_key", "API_KEY",
         _c(r"\bsk-[A-Za-z0-9_-]{20,}\b"), 0.80, validator=not_placeholder),
    Rule("key_assignment", "API_KEY",
         _c(r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{16,})", re.I),
         0.70, group=1, validator=not_placeholder),
    Rule("password_ctx", "PASSWORD",
         _c(r"\b(?:password|passwd|pwd|pass)\b\s*(?:is|[:=])\s*['\"]?([^\s'\",;]{4,})", re.I),
         0.75, group=1, validator=password_like),
    Rule("private_key", "PRIVATE_KEY",
         _c(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|\Z)"),
         0.99),
    Rule("db_conn", "DB_CONNECTION_STRING",
         _c(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]+:[^\s@/]+@[^\s'\"<>]*[^\s'\"<>.,;)]", re.I),
         0.95),

    Rule("jwt", "JWT_TOKEN",
         _c(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), 0.90),
    Rule("google_key", "API_KEY",
         _c(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"), 0.95),
    Rule("stripe_key", "API_KEY",
         _c(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"), 0.95),
    Rule("upi", "UPI_ID",
         _c(r"(?<![\w.+-])[A-Za-z0-9._-]{2,}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|ibl|axl|paytm|upi|apl|axisb|sbi|icici|hdfcbank|fbl)(?![\w-])(?!\.[A-Za-z0-9])"),
         0.85),
    Rule("ifsc", "IFSC",
         _c(r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])"),
         0.70, validator=ifsc_ok, context=("ifsc", "branch"), boosted_score=0.95),
    Rule("bank_account", "BANK_ACCOUNT",
         _c(r"\b(?:account|a/c|acct)\b(?:\s+(?:number|no\.?|num|#))?\s*(?:is|[:=-])?\s*([0-9]{9,18})(?![0-9])", re.I),
         0.80, group=1),
    Rule("passport", "PASSPORT",
         _c(r"\bpassport\b(?:\s+(?:number|no\.?|num|#))?\s*(?:is|[:=-])?\s*([A-PR-WY][0-9]{7})(?![0-9A-Za-z])", re.I),
         0.85, group=1),
    Rule("dob", "DATE_OF_BIRTH",
         _c(r"\b(?:dob|date of birth|birth ?date|born on|birthday)\b\s*(?:is|[:=-])?\s*"
            r"((?:[0-9]{1,2}[/.-][0-9]{1,2}[/.-][0-9]{2,4})|(?:[0-9]{4}-[0-9]{2}-[0-9]{2}))", re.I),
         0.80, group=1),
    Rule("address_ctx", "ADDRESS",
         _c(r"\b(?:address|location|residing at|lives at|living at|staying at|stay at)\b\s*(?:is|[:=-])?\s*([^\n.;]{10,100})", re.I),
         0.55, group=1, validator=has_digit),
    Rule("ipv4", "IP_ADDRESS",
         _c(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])(?!\.[0-9])"),
         0.60, validator=valid_ipv4, context=("ip", "server", "host"), boosted_score=0.85),
)


def _has_context(text: str, start: int, words: tuple) -> bool:
    window = text[max(0, start - CONTEXT_WINDOW):start].lower()
    return any(w in window for w in words)


# ---------------------------------------------------------------------------
# Address heuristic: Indian-style addresses without a trigger word.
# A clause is treated as an address when an address keyword (road, hostel,
# flat, sector, ...) sits next to a house/room/sector number or a 6-digit
# pincode. Short numbers must touch the keyword so that "sector grew 5%" or
# "banking sector 2024" is not flagged.
# ---------------------------------------------------------------------------
_ADDR_KEYS = {"hostel", "road", "rd", "street", "nagar", "colony", "sector", "flat",
              "apartment", "apartments", "lane", "marg", "chowk", "enclave", "vihar",
              "pincode", "pin"}
_PIN_ONLY = {"pincode", "pin"}
_ROAD_LIKE = {"road", "rd", "street", "lane", "marg", "colony", "nagar"}
_FILLER = {"no", "no.", "number", "#", "-", ":", "num", "nos", "code"}
_SHORT_NUM = re.compile(r"^[a-z]{0,3}[-/]?[0-9]{1,3}[a-z]?$")
_PIN = re.compile(r"^[1-9][0-9]{5}$")
_STOP = {"my", "i", "am", "is", "are", "at", "in", "on", "the", "a", "an", "to", "from",
         "near", "stay", "staying", "stays", "live", "living", "lives", "address",
         "location", "reside", "residing", "of", "and", "hi", "hello", "hey", "please",
         "located", "situated", "its", "it's", "we", "our", "this", "that", "here",
         "there", "for", "with", "by", "send", "deliver", "ship", "it", ""}
_CLAUSE = re.compile(r"[^\n;!?]+")
_TOKEN = re.compile(r"\S+")


def _clean_tok(t: str) -> str:
    return t.strip(",.;:()[]{}\"'").lower()


def detect_addresses(text: str) -> list[Finding]:
    out: list[Finding] = []
    for cm in _CLAUSE.finditer(text):
        base = cm.start()
        toks = [(m.start() + base, m.end() + base) for m in _TOKEN.finditer(cm.group())]
        cl = [_clean_tok(text[a:b]) for a, b in toks]
        n, used_until = len(cl), -1
        for i, w in enumerate(cl):
            if w not in _ADDR_KEYS or i <= used_until:
                continue
            start_tok, end_tok, has_pin = i, None, False
            j = i + 1
            while j < n and j <= i + 3 and cl[j] in _FILLER:
                j += 1
            if j < n and _PIN.match(cl[j]):
                end_tok, has_pin = j, True
            elif j < n and w not in _PIN_ONLY and _SHORT_NUM.match(cl[j]):
                end_tok = j
            else:
                for k in range(i + 1, min(n, i + 4)):        # "Road, Pune 411001"
                    if _PIN.match(cl[k]):
                        end_tok, has_pin = k, True
                        break
            if end_tok is None and w in _ROAD_LIKE:           # "12 MG Road"
                for k in (i - 2, i - 3):
                    if k >= 0 and _SHORT_NUM.match(cl[k]) and any(c.isdigit() for c in cl[k]):
                        start_tok, end_tok = k, i
                        break
            if end_tok is None:
                continue
            for k in range(end_tok + 1, min(n, end_tok + 5)):  # trailing pincode
                if _PIN.match(cl[k]):
                    end_tok, has_pin = k, True
                    break
            back = 0
            while back < 4 and start_tok - 1 >= 0 and cl[start_tok - 1] not in _STOP:
                start_tok -= 1
                back += 1
            s, e = toks[start_tok][0], toks[end_tok][1]
            while e > s and text[e - 1] in ",.;:)":
                e -= 1
            while s < e and text[s] in "(":
                s += 1
            if e - s >= 4:
                out.append(Finding("ADDRESS", s, e, 0.70 if has_pin else 0.60,
                                   "rule:address_pattern"))
            used_until = end_tok
    return out


class RuleDetector(Detector):
    name = "rules"

    def __init__(self, rules: tuple[Rule, ...] = RULES):
        self.rules = rules

    def detect(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                s, e = m.span(rule.group)
                if s < 0 or e <= s:
                    continue
                if rule.validator and not rule.validator(text[s:e]):
                    continue
                score = rule.score
                if rule.context and _has_context(text, s, rule.context):
                    score = max(score, rule.boosted_score)
                out.append(Finding(rule.entity, s, e, score, f"rule:{rule.name}"))
        out.extend(detect_addresses(text))
        return out


class KeywordDetector(Detector):
    """Organisation-specific confidential terms (expanded in Milestone 2)."""
    name = "keywords"

    def __init__(self, keywords):
        kws = sorted({k.strip() for k in keywords if k and k.strip()},
                     key=len, reverse=True)
        self._pattern = (re.compile(
            r"(?<!\w)(?:" + "|".join(re.escape(k) for k in kws) + r")(?!\w)",
            re.I) if kws else None)

    def detect(self, text: str) -> list[Finding]:
        if not self._pattern:
            return []
        return [Finding("CUSTOM_KEYWORD", m.start(), m.end(), 0.90, "keywords")
                for m in self._pattern.finditer(text)]
