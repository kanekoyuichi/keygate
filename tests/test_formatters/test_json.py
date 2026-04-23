from __future__ import annotations

import json

from keygate.formatters import json as json_formatter
from keygate.models import (
    DiffLine,
    RuleMatch,
    ScanReport,
    ScanResult,
    ScanSummary,
    Verdict,
)


def _result(
    rule_matches: list[RuleMatch],
    *,
    file: str = "src/app.py",
    line: int = 10,
    score: int = 80,
    verdict: Verdict = Verdict.BLOCK,
    reason: str = "Suspicious pattern",
) -> ScanResult:
    return ScanResult(
        diff_line=DiffLine(file_path=file, line_number=line, content="x"),
        total_score=score,
        verdict=verdict,
        rule_matches=rule_matches,
        score_breakdown={},
        reason=reason,
    )


def _report(blocked: list[ScanResult], warned: list[ScanResult], scanned_lines: int = 5) -> ScanReport:
    if blocked:
        status = "block"
    elif warned:
        status = "warn"
    else:
        status = "pass"
    summary = ScanSummary(
        findings=len(blocked) + len(warned),
        blocked=len(blocked),
        warned=len(warned),
        scanned_lines=scanned_lines,
    )
    return ScanReport(status=status, summary=summary, blocked=blocked, warned=warned)


def test_schema_version_is_fixed():
    payload = json.loads(json_formatter.format(_report([], [])))
    assert payload["schema_version"] == "1"


def test_required_fields_present():
    match = RuleMatch(
        rule_id="openai-api-key",
        matched_text="sk-abcdefghijklmnop",
        score=85,
        description="OpenAI API Key detected",
        policy="must_block",
    )
    payload = json.loads(json_formatter.format(_report([_result([match])], [])))
    assert {"schema_version", "status", "summary", "findings"} <= payload.keys()
    finding = payload["findings"][0]
    assert {"score", "verdict", "file", "line", "message"} <= finding.keys()


def test_must_block_policy_is_emitted():
    match = RuleMatch(
        rule_id="aws-access-key",
        matched_text="AKIAABCDEFGHIJKLMNOP",  # keygate: ignore reason="test fixture"
        score=90,
        description="AWS Access Key detected",
        policy="must_block",
    )
    payload = json.loads(json_formatter.format(_report([_result([match])], [])))
    assert payload["findings"][0]["policy"] == "must_block"
    assert payload["findings"][0]["rule_id"] == "aws-access-key"


def test_public_exposable_policy_is_emitted():
    match = RuleMatch(
        rule_id="stripe-publishable-key",
        matched_text="pk_live_xxxxxxxxxxxxxxxxxxxxxxxx",  # keygate: ignore reason="test fixture"
        score=40,
        description="Stripe Live Publishable Key detected",
        policy="public_exposable",
    )
    payload = json.loads(json_formatter.format(_report([], [_result([match], verdict=Verdict.WARN, score=40)])))
    assert payload["findings"][0]["policy"] == "public_exposable"


def test_generic_signal_has_null_rule_id_and_policy():
    """Generic signal (no rule match) should produce rule_id=null, policy=null."""
    payload = json.loads(json_formatter.format(_report([], [_result([], verdict=Verdict.WARN, score=45)])))
    finding = payload["findings"][0]
    assert finding["rule_id"] is None
    assert finding["policy"] is None
    assert finding["recommended_action"] == "manual_review"


def test_summary_counts_match_findings():
    m = RuleMatch(rule_id="aws-access-key", matched_text="AKIA0000000000000000", score=90, description="x", policy="must_block")  # keygate: ignore reason="test fixture"
    payload = json.loads(json_formatter.format(_report([_result([m])], [_result([m], verdict=Verdict.WARN, score=45)])))
    assert payload["summary"]["findings"] == 2
    assert payload["summary"]["blocked"] == 1
    assert payload["summary"]["warned"] == 1


def test_recommended_action_for_known_rule():
    m = RuleMatch(rule_id="openai-api-key", matched_text="sk-abcdef0123456789abcd", score=85, description="x", policy="must_block")  # keygate: ignore reason="test fixture"
    payload = json.loads(json_formatter.format(_report([_result([m])], [])))
    assert payload["findings"][0]["recommended_action"] == "move_to_secret_manager"


def test_snippet_is_masked_when_present():
    m = RuleMatch(
        rule_id="openai-api-key",
        matched_text="sk-abcdef0123456789abcdef0123456789abcd",  # keygate: ignore reason="test fixture"
        score=85,
        description="x",
        policy="must_block",
    )
    payload = json.loads(json_formatter.format(_report([_result([m])], [])))
    snippet = payload["findings"][0].get("snippet")
    assert snippet is not None
    assert "***" in snippet
    # Original secret must not leak
    assert "abcdef0123456789abcdef" not in snippet


def test_snippet_omitted_for_short_match():
    m = RuleMatch(rule_id="x", matched_text="short", score=10, description="x")
    payload = json.loads(json_formatter.format(_report([], [_result([m], verdict=Verdict.WARN, score=45)])))
    assert "snippet" not in payload["findings"][0]


def test_pass_status_has_empty_findings():
    payload = json.loads(json_formatter.format(_report([], [])))
    assert payload["status"] == "pass"
    assert payload["findings"] == []
    assert payload["summary"]["findings"] == 0


def test_status_is_block_when_block_present():
    m = RuleMatch(rule_id="aws-access-key", matched_text="AKIA0000000000000000", score=90, description="x", policy="must_block")  # keygate: ignore reason="test fixture"
    payload = json.loads(json_formatter.format(_report([_result([m])], [_result([m], verdict=Verdict.WARN, score=45)])))
    assert payload["status"] == "block"


def test_status_is_warn_when_only_warn_present():
    m = RuleMatch(rule_id="stripe-publishable-key", matched_text="pk_live_xxxxxxxxxxxxxxxxxxxx", score=40, description="x", policy="public_exposable")
    payload = json.loads(json_formatter.format(_report([], [_result([m], verdict=Verdict.WARN, score=40)])))
    assert payload["status"] == "warn"
