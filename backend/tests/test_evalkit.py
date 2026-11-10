import re
from app.evalkit import dataset, metrics
from app.detectors.validators import luhn_valid, verhoeff_valid, digits_only


def test_dataset_deterministic_and_valid(tmp_path):
    a, b = dataset.generate(seed=7), dataset.generate(seed=7)
    assert a == b and a != dataset.generate(seed=8)
    dataset.validate(a)
    dataset.save(a, tmp_path)
    assert dataset.load(tmp_path) == a


def test_label_spans_are_correct_values():
    docs = dataset.generate(seed=1)
    seen = set()
    for d in docs:
        for e in d["entities"]:
            v, lab = d["text"][e["start"]:e["end"]], e["label"]
            seen.add(lab)
            if lab == "EMAIL_ADDRESS": assert "@" in v
            if lab == "AADHAAR": assert verhoeff_valid(v)
            if lab == "CREDIT_CARD": assert luhn_valid(v)
            if lab == "PAN": assert re.fullmatch(r"[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]", v)
            if lab == "PRIVATE_KEY": assert v.startswith("-----BEGIN") and v.endswith("-----")
            if lab == "IP_ADDRESS": assert v.count(".") == 3
    assert seen == set(dataset.LABELS)


def test_kinds_present():
    kinds = {d["kind"] for d in dataset.generate()}
    assert kinds == {"positive", "negative", "hard_negative"}
    assert all(d["entities"] == [] for d in dataset.generate() if d["kind"] != "positive")


def test_hard_negatives_are_not_valid_values():
    for d in dataset.generate(seed=3):
        if "Reference id" in d["text"]:
            assert not verhoeff_valid(digits_only(d["text"]))  # checksum really fails


def test_strict_metrics():
    acc = {}
    gold = [("EMAIL", 0, 5), ("EMAIL", 10, 15)]
    pred = [("EMAIL", 0, 5), ("EMAIL", 10, 14), ("EMAIL", 20, 25)]
    metrics.count_doc(pred, gold, ["EMAIL"], False, acc)
    s = metrics.summarise(acc)["overall"]
    assert (s["tp"], s["fp"], s["fn"]) == (1, 2, 1)
    assert round(s["precision"], 3) == 0.333 and s["recall"] == 0.5


def test_lenient_metrics_credit_partial_overlap():
    acc = {}
    metrics.count_doc([("E", 10, 14)], [("E", 10, 15)], ["E"], True, acc)
    s = metrics.summarise(acc)["overall"]
    assert s["precision"] == 1.0 and s["recall"] == 1.0


def test_label_mismatch_not_counted():
    acc = {}
    metrics.count_doc([("A", 0, 5)], [("B", 0, 5)], ["A", "B"], False, acc)
    s = metrics.summarise(acc)["overall"]
    assert s["tp"] == 0 and s["fp"] == 1 and s["fn"] == 1


def test_leakage_and_percentile():
    assert metrics.leaked(["abc", "xyz"], "hello abc") == 1
    assert metrics.percentile([1, 2, 3, 4, 100], 0.95) == 100
    assert metrics.percentile([], 0.5) == 0.0
