from __future__ import annotations

from keygate.formatters import text as text_formatter
from keygate.models import (
    DiffLine,
    RuleMatch,
    ScanReport,
    ScanResult,
    ScanSummary,
    Verdict,
)


def _block_report() -> ScanReport:
    line = DiffLine(file_path=".env", line_number=3, content="x")
    match = RuleMatch(
        rule_id="openai-api-key",
        matched_text="sk-abcdef0123456789",
        score=85,
        description="OpenAI API Key detected",
        remediation=["Remove the key from the code"],
        policy="must_block",
    )
    result = ScanResult(
        diff_line=line,
        total_score=90,
        verdict=Verdict.BLOCK,
        rule_matches=[match],
        score_breakdown={},
        reason="OpenAI API Key detected",
    )
    return ScanReport(
        status="block",
        summary=ScanSummary(findings=1, blocked=1, warned=0, scanned_lines=3),
        blocked=[result],
        warned=[],
    )


def _pass_report() -> ScanReport:
    return ScanReport(
        status="pass",
        summary=ScanSummary(findings=0, blocked=0, warned=0, scanned_lines=2),
        blocked=[],
        warned=[],
    )


def test_summary_line_first():
    output = text_formatter.format(_block_report())
    assert output.splitlines()[0] == "[KEYGATE] status=block findings=1"


def test_summary_line_on_pass():
    output = text_formatter.format(_pass_report())
    assert output.splitlines()[0] == "[KEYGATE] status=pass findings=0"


def test_block_includes_rerun_notice():
    output = text_formatter.format(_block_report())
    assert "KeyGate detected secrets and blocked this commit." in output
    assert "keygate scan --format json" in output


def test_pass_excludes_rerun_notice():
    output = text_formatter.format(_pass_report())
    assert "keygate scan --format json" not in output
    assert "KeyGate detected" not in output


def test_finding_includes_file_and_score():
    output = text_formatter.format(_block_report())
    assert ".env:3" in output
    assert "Score: 90" in output
    assert "Rule: openai-api-key" in output
