from __future__ import annotations

from pathlib import Path

from keygate.scanner.rules import scan_line

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _positive_cases() -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []
    for raw in (FIXTURES / "positive" / "rules.tsv").read_text().splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        rule_id, content = raw.split("\t", 1)
        cases.append((rule_id, content))
    return cases


def _negative_cases() -> list[str]:
    return [
        raw for raw in (FIXTURES / "negative" / "rules.txt").read_text().splitlines()
        if raw.strip() and not raw.startswith("#")
    ]


def test_positive_rule_corpus_matches_expected_rule_ids():
    for rule_id, content in _positive_cases():
        matches = scan_line(content)
        rule_ids = {m.rule_id for m in matches}
        assert rule_id in rule_ids, f"Expected {rule_id} for {content!r}, got {rule_ids}"


def test_negative_rule_corpus_has_no_matches():
    for content in _negative_cases():
        assert scan_line(content) == [], f"Unexpected match for {content!r}"
