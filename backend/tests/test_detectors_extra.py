import time
import pytest
from app.engine import Scanner, apply_masking, cluster_overlaps
from app.models import Finding

sc = Scanner("rules")

CASES = [
    ("jwt", "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEF123456xyz here", {"JWT_TOKEN"}),
    ("google", "key AIzaSyA1234567890abcdefghijklmnopqrstuv", {"API_KEY"}),
    ("stripe", "use sk_live_abcdefghijklmnop1234 for billing", {"API_KEY"}),
    ("github", "GITHUB_TOKEN=ghp_" + "a1B2c3D4e5" * 4, {"API_KEY"}),
    ("upi", "pay to ravi@okaxis today", {"UPI_ID"}),
    ("ifsc", "IFSC code HDFC0001234 for the branch", {"IFSC"}),
    ("bank_acct", "my account number is 123456789012", {"BANK_ACCOUNT"}),
    ("passport", "passport no: K1234567 expires 2030", {"PASSPORT"}),
    ("dob", "DOB: 12/05/1999", {"DATE_OF_BIRTH"}),
    ("dob_iso", "born on 1999-05-12 in the city", {"DATE_OF_BIRTH"}),
    ("address", "my address is 12 MG Road, Pune 411001", {"ADDRESS"}),
    ("location_addr", "my location is jalandhar, punjab lpu boys hostel bh5", {"ADDRESS"}),
    ("ip", "server ip 10.0.0.5 is down", {"IP_ADDRESS"}),
    ("phone_ctx", "this is my phone number 1234567890 message me", {"PHONE_NUMBER"}),
    ("hinglish_phone", "mera phone number 98765 43210 hai", {"PHONE_NUMBER"}),
    ("hinglish_email", "mera email ravi.k@example.in hai", {"EMAIL_ADDRESS"}),
    ("hindi_phone", "फोन 91234 56789", {"PHONE_NUMBER"}),
]
NEGATIVES = [
    "Address is required for delivery",           # no digit -> not an address
    "invalid ip 999.1.1.1 given",                 # bad octet
    "Order number 1234567890 was shipped.",       # no phone context
    "passport photo size is 35x45",               # not a passport number
    "the account was closed last year",           # no digits
    "eyJ is a prefix and not a token",            # too short for JWT
    "Born on a Monday",                           # no date
    "My location is Jalandhar",                   # place name only, no digit
]


@pytest.mark.parametrize("name,text,expect", CASES, ids=[c[0] for c in CASES])
def test_new_detectors(name, text, expect):
    got = {f.entity_type for f in sc.scan(text).findings}
    assert expect <= got, f"{name}: expected {expect}, got {got}"


@pytest.mark.parametrize("text", NEGATIVES)
def test_new_hard_negatives(text):
    assert sc.scan(text).findings == []


def test_offsets_with_astral_unicode():
    text = "😀 mail a@example.com 🎉 PAN ABCPE1234F"
    r = sc.scan(text)
    values = {text[f.start:f.end] for f in r.findings}
    assert values == {"a@example.com", "ABCPE1234F"}


def test_numbered_masking_and_mapping():
    text = "a@example.com wrote to b@example.com and a@example.com again"
    r = sc.scan(text)
    masked, mapping = apply_masking(text, r.clusters, numbered=True)
    assert masked == "[EMAIL_ADDRESS_1] wrote to [EMAIL_ADDRESS_2] and [EMAIL_ADDRESS_1] again"
    assert mapping["[EMAIL_ADDRESS_1]"] == "a@example.com"


def test_overlap_cluster_masks_union():
    text = "xx0123456789yy"
    f1 = Finding("PERSON", 2, 8, 0.9, "t")
    f2 = Finding("PHONE_NUMBER", 5, 12, 0.6, "t")
    masked, _ = apply_masking(text, cluster_overlaps([f1, f2]))
    assert masked == "xx[PERSON]yy"          # no digit fragment survives


@pytest.mark.parametrize("payload", [
    "1 " * 50000, "-" * 100000, "9" * 100000, "a@" * 40000,
    "password: " * 10000, "AKIA" * 25000, "-----BEGIN PRIVATE KEY-----" + "A" * 90000,
    "1234 " * 20000, "http://" + "a:" * 30000,
])
def test_adversarial_inputs_finish_quickly(payload):
    t0 = time.perf_counter()
    sc.scan(payload[:100000])
    assert time.perf_counter() - t0 < 5.0


def test_keywords_case_insensitive_and_word_bounded():
    s = Scanner("rules", ["Project Falcon"])
    assert len(s.scan("project falcon is on").findings) == 1
    assert s.scan("Project Falconry").findings == []


ADDRESS_YES = [
    ("my location is jalandhar, punjab lpu boys hostel bh5", "bh5"),
    ("I stay near Phagwara gate, flat 12 for now", "flat 12"),
    ("Send it to 12 MG Road, Pune 411001", "411001"),
    ("pincode 144411", "144411"),
    ("pin code 144411 please", "144411"),
    ("lives in Gandhi Nagar sector 7", "sector 7"),
    ("Room at LPU boys hostel BH5, Phagwara", "BH5"),
]
ADDRESS_NO = [
    "The banking sector grew 5% in 2024",
    "Road accidents rose last year",
    "5 road accidents were reported",
    "Use a flat structure for the config",
    "Plot 3 shows the loss curve",
    "OTP is 123456",
    "Order number 123456 shipped",
    "The sector is growing fast",
]


@pytest.mark.parametrize("text,must_cover", ADDRESS_YES)
def test_address_heuristic_detects_and_masks(text, must_cover):
    r = sc.scan(text)
    assert "ADDRESS" in {f.entity_type for f in r.findings}
    assert must_cover not in r.sanitized_text          # masking covers it


@pytest.mark.parametrize("text", ADDRESS_NO)
def test_address_heuristic_false_positive_guards(text):
    assert "ADDRESS" not in {f.entity_type for f in sc.scan(text).findings}
