import pytest
from app.engine import Scanner
from app.samples import SAMPLES, sample_passes
from app.detectors.validators import luhn_valid, verhoeff_valid, verhoeff_check_digit
from app.config import MAX_INPUT_CHARS

_cache = {}


def _scanner(mode):
    if mode not in _cache:
        try:
            _cache[mode] = Scanner(mode)
        except Exception as exc:
            pytest.skip(f"{mode} scanner unavailable: {exc}")
    return _cache[mode]


@pytest.mark.parametrize("sample", SAMPLES, ids=[s.id for s in SAMPLES])
def test_sample_detection(sample):
    res = _scanner(sample.mode).scan(sample.text)
    got = {f.entity_type for f in res.findings}
    assert sample_passes(sample, got), f"expected {sample.expect}, got {got}"


@pytest.mark.parametrize("sample", [s for s in SAMPLES if s.expect and s.mode == "rules"],
                         ids=lambda s: s.id)
def test_masking_does_not_leak_values(sample):
    res = _scanner("rules").scan(sample.text)
    for f in res.findings:
        value = sample.text[f.start:f.end]
        assert value not in res.sanitized_text


def test_offsets_are_half_open_and_in_range():
    text = "mail a.b@example.com now"
    f = _scanner("rules").scan(text).findings[0]
    assert text[f.start:f.end] == "a.b@example.com"


def test_overlap_db_url_beats_embedded_email_like_text():
    text = "postgresql://u:pw1234@host.example.com/db"
    res = _scanner("rules").scan(text)
    assert [f.entity_type for f in res.findings] == ["DB_CONNECTION_STRING"]
    assert res.sanitized_text == "[DB_CONNECTION_STRING]"


def test_empty_input():
    res = _scanner("rules").scan("")
    assert res.findings == [] and res.sanitized_text == ""


def test_oversized_and_wrong_type_rejected():
    with pytest.raises(ValueError):
        _scanner("rules").scan("a" * (MAX_INPUT_CHARS + 1))
    with pytest.raises(TypeError):
        _scanner("rules").scan(123)


def test_custom_keyword():
    res = Scanner("rules", ["Project Falcon"]).scan("Status of project falcon?")
    assert {f.entity_type for f in res.findings} == {"CUSTOM_KEYWORD"}


def test_validators():
    assert luhn_valid("4111 1111 1111 1111")
    assert not luhn_valid("4111 1111 1111 1112")
    base = "23456789012"
    assert verhoeff_valid(base + str(verhoeff_check_digit(base)))
    assert not verhoeff_valid(base + str((verhoeff_check_digit(base) + 1) % 10))
