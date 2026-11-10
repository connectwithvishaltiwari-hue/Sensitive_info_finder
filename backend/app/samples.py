from dataclasses import dataclass, field
from .detectors.validators import verhoeff_check_digit


def _aadhaar_like(valid: bool = True) -> str:
    base = "23456789012"
    d = verhoeff_check_digit(base)
    if not valid:
        d = (d + 1) % 10
    n = base + str(d)
    return f"{n[:4]} {n[4:8]} {n[8:]}"


@dataclass(frozen=True)
class Sample:
    id: str
    text: str
    expect: frozenset
    mode: str = "rules"
    exact: bool = True            # detected types must equal expect
    forbid: frozenset = field(default_factory=frozenset)


def _s(i, text, expect=(), **kw):
    return Sample(i, text, frozenset(expect), **kw)


SAMPLES = [
    _s("email", "Please contact priya.sharma@example.com about the invoice.", {"EMAIL_ADDRESS"}),
    _s("phone_in", "Call me on +91 98765 43210 after 5 pm.", {"PHONE_NUMBER"}),
    _s("phone_generic_ctx", "this is my phone number 1234567890 message me", {"PHONE_NUMBER"}),
    _s("number_no_phone_context", "Order number 1234567890 was shipped.", ()),
    _s("aadhaar_valid", f"My Aadhaar number is {_aadhaar_like(True)}.", {"AADHAAR"}),
    _s("aadhaar_bad_checksum", f"Reference id {_aadhaar_like(False)} was logged.", (), forbid={"AADHAAR"}),
    _s("pan", "My PAN is ABCPE1234F for the tax filing.", {"PAN"}),
    _s("pan_lookalike", "Part number ABCDE1234F is in stock.", ()),
    _s("card_valid", "Pay with credit card 4111 1111 1111 1111 today.", {"CREDIT_CARD"}),
    _s("card_bad_luhn", "Order code 4111 1111 1111 1112 shipped.", (), forbid={"CREDIT_CARD"}, exact=False),
    _s("aws_key", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", {"API_KEY"}),
    _s("password", "login with username admin and password: Tr0ub4dor&3 today", {"PASSWORD"}),
    _s("password_negative", "Password is required for login.", ()),
    _s("api_placeholder", "Set api_key = YOUR_API_KEY_HERE in the config file.", ()),
    _s("private_key", "-----BEGIN PRIVATE KEY-----\nMIIFAKEFAKEFAKE\n-----END PRIVATE KEY-----", {"PRIVATE_KEY"}),
    _s("db_conn", "DATABASE_URL=postgresql://appuser:S3cretPass9@db.internal.example.com:5432/orders", {"DB_CONNECTION_STRING"}),
    _s("multi", "Reach Meera at meera.k@example.org or 98765 43210; her PAN is ABCPE1234F.", {"EMAIL_ADDRESS", "PHONE_NUMBER", "PAN"}),
    _s("unicode", "संपर्क: ravi.kumar@example.in, फोन +91 91234 56789", {"EMAIL_ADDRESS", "PHONE_NUMBER"}),
    _s("benign", "Explain how gradient descent works.", ()),
    _s("person_nlp", "Ananya Iyer sent the report to John Smith.", {"PERSON"}, mode="hybrid", exact=False),
]


def sample_passes(sample: Sample, detected_types: set) -> bool:
    if not sample.expect <= detected_types:
        return False
    if sample.exact and detected_types != sample.expect:
        return False
    return not (sample.forbid & detected_types)
