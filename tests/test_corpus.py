import json
from collections import Counter
from pathlib import Path

CORPUS = Path(__file__).resolve().parents[1] / "bench" / "corpus.jsonl"

EXPECTED_COUNTS = {
    "direct_jailbreak": 12,
    "indirect_injection": 8,
    "exfil": 6,
    "guard_manipulation": 4,
    "benign_plain": 16,
    "benign_lookalike": 14,
}


def load():
    return [json.loads(line) for line in CORPUS.read_text().splitlines() if line.strip()]


def test_corpus_has_sixty_cases():
    assert len(load()) == 60


def test_category_quotas_are_met():
    assert Counter(case["category"] for case in load()) == EXPECTED_COUNTS


def test_ids_are_unique():
    cases = load()
    assert len({case["id"] for case in cases}) == len(cases)


def test_every_case_has_the_required_keys():
    required = {"id", "label", "category", "expect_block", "user_message", "untrusted_content"}
    for case in load():
        assert set(case) == required, case["id"]
        assert case["label"] in {"attack", "benign"}
        assert isinstance(case["expect_block"], bool)
        assert isinstance(case["user_message"], str) and case["user_message"].strip()


def test_labels_and_expectations_agree():
    for case in load():
        assert case["expect_block"] is (case["label"] == "attack"), case["id"]


def test_benign_cases_are_at_least_half_the_corpus():
    cases = load()
    benign = [c for c in cases if c["label"] == "benign"]
    # An attack-heavy corpus would let `return BLOCK` score near-perfectly.
    assert len(benign) >= len(cases) / 2


def test_most_benign_cases_are_lookalikes():
    benign = [c for c in load() if c["label"] == "benign"]
    lookalikes = [c for c in benign if c["category"] == "benign_lookalike"]
    assert len(lookalikes) >= len(benign) * 0.4


def test_untrusted_content_shape():
    for case in load():
        blocks = case["untrusted_content"]
        if blocks is None:
            continue
        for block in blocks:
            assert set(block) == {"source", "text"}, case["id"]
            assert block["source"] in {"tool_result", "document"}
            assert block["text"].strip()


def test_injection_cases_all_carry_untrusted_content():
    for case in load():
        if case["category"] == "indirect_injection":
            assert case["untrusted_content"], case["id"]


def test_some_benign_cases_carry_untrusted_content():
    # Otherwise the injection question is only ever exercised on attacks.
    benign_with_untrusted = [
        c for c in load() if c["label"] == "benign" and c["untrusted_content"]
    ]
    assert len(benign_with_untrusted) >= 5
