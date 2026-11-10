import pytest
from pydantic import ValidationError
from app.engine import Scanner, cluster_overlaps
from app.models import Finding
from app.policies.engine import PolicySettings, default_policy, evaluate

sc = Scanner("rules")


def decide(text, policy=None, output=False):
    res = sc.scan(text)
    return evaluate(res.clusters, policy or default_policy(), output)


def test_defaults_credentials_block_pii_mask_benign_allow():
    assert decide("key AKIAIOSFODNN7EXAMPLE").overall == "BLOCK"
    assert decide("mail a@example.com").overall == "MASK"
    assert decide("Explain gradient descent").overall == "ALLOW"


def test_mixed_block_dominates():
    assert decide("mail a@example.com key AKIAIOSFODNN7EXAMPLE").overall == "BLOCK"


def test_low_confidence_becomes_warn():
    p = PolicySettings(warn_below=0.7)      # bare phone scores 0.60
    d = decide("ref 98765 43210 soon", p)
    assert d.overall == "WARN" and "low confidence" in d.items[0]["reason"]


def test_ignore_threshold():
    p = PolicySettings(ignore_below=0.65, warn_below=0.65)
    assert decide("98765 43210", p).overall == "ALLOW"


def test_custom_action_per_entity():
    p = PolicySettings()
    p.entity_actions["EMAIL_ADDRESS"] = "BLOCK"
    assert decide("a@example.com", p).overall == "BLOCK"
    p.entity_actions["EMAIL_ADDRESS"] = "ALLOW"
    assert decide("a@example.com", p).overall == "ALLOW"


def test_cluster_protection_mask_beats_warn():
    c = cluster_overlaps([Finding("PERSON", 0, 5, 0.9, "t"), Finding("ADDRESS", 0, 5, 0.9, "t")])
    d = evaluate(c, default_policy())
    assert d.cluster_actions == ["MASK"]            # never leave the span exposed


def test_overall_precedence_warn_over_mask():
    c = [[Finding("EMAIL_ADDRESS", 0, 3, .9, "t")], [Finding("ADDRESS", 5, 9, .9, "t")]]
    assert evaluate(c, default_policy()).overall == "WARN"


def test_output_converts_warn_to_mask():
    c = [[Finding("ADDRESS", 0, 9, .9, "t")]]
    assert evaluate(c, default_policy()).overall == "WARN"
    assert evaluate(c, default_policy(), output=True).overall == "MASK"


def test_settings_validation():
    with pytest.raises(ValidationError):
        PolicySettings(entity_actions={"NOT_A_THING": "MASK"})
    with pytest.raises(ValidationError):
        PolicySettings(ignore_below=0.8, warn_below=0.2)
    with pytest.raises(ValidationError):
        PolicySettings(ignore_below=1.5)
    with pytest.raises(ValidationError):
        PolicySettings(custom_keywords=["x" * 101])
    with pytest.raises(ValidationError):
        PolicySettings(entity_actions={"EMAIL_ADDRESS": "DELETE"})
