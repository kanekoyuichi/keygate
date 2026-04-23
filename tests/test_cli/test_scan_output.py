from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from keygate import cli
from keygate.models import (
    DiffLine,
    RuleMatch,
    ScanReport,
    ScanResult,
    ScanSummary,
    Verdict,
)


def _make_block_report() -> ScanReport:
    line = DiffLine(file_path=".env", line_number=3, content="OPENAI_API_KEY=sk-abcdef0123456789abcdef0123456789abcd")  # keygate: ignore reason="test fixture"
    match = RuleMatch(
        rule_id="openai-api-key",
        matched_text="sk-abcdef0123456789abcdef0123456789abcd",  # keygate: ignore reason="test fixture"
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
        score_breakdown={"rule:openai-api-key": 85, "entropy": 5},
        reason="OpenAI API Key detected",
    )
    summary = ScanSummary(findings=1, blocked=1, warned=0, scanned_lines=3)
    return ScanReport(status="block", summary=summary, blocked=[result], warned=[])


def _make_pass_report() -> ScanReport:
    summary = ScanSummary(findings=0, blocked=0, warned=0, scanned_lines=2)
    return ScanReport(status="pass", summary=summary, blocked=[], warned=[])


@pytest.fixture
def patch_block(monkeypatch):
    monkeypatch.setattr(cli, "_run_scan", lambda _root: _make_block_report())


@pytest.fixture
def patch_pass(monkeypatch):
    monkeypatch.setattr(cli, "_run_scan", lambda _root: _make_pass_report())


def test_scan_default_is_text(patch_block):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["scan"])
    assert result.exit_code == 1
    assert "[KEYGATE] status=block findings=1" in result.output
    # JSON should not appear in default text output
    assert "schema_version" not in result.output


def test_scan_format_json_outputs_only_json(patch_block):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["scan", "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1"
    assert payload["status"] == "block"
    assert payload["summary"]["findings"] == 1
    # Text headlines must not be mixed into JSON output
    assert "[KEYGATE]" not in result.output
    assert "High confidence" not in result.output


def test_scan_json_flag_is_alias_for_format_json(patch_block):
    runner = CliRunner()
    a = runner.invoke(cli.main, ["scan", "--json"])
    b = runner.invoke(cli.main, ["scan", "--format", "json"])
    assert a.exit_code == b.exit_code == 1
    assert json.loads(a.output) == json.loads(b.output)


def test_scan_profile_agent_outputs_only_json(patch_block):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["scan", "--profile", "agent"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1"
    assert "[KEYGATE]" not in result.output


def test_scan_conflicting_options_fail(patch_block):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["scan", "--format", "text", "--json"])
    # click.UsageError exits with code 2
    assert result.exit_code == 2


def test_scan_text_includes_rerun_notice_on_block(patch_block):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["scan"])
    assert "keygate scan --format json" in result.output
    assert "KeyGate detected secrets" in result.output


def test_scan_pass_text_summary_no_rerun_notice(patch_pass):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["scan"])
    assert result.exit_code == 0
    assert "[KEYGATE] status=pass findings=0" in result.output
    # No rerun notice on pass
    assert "KeyGate detected secrets" not in result.output


def test_scan_pass_json_status(patch_pass):
    runner = CliRunner()
    result = runner.invoke(cli.main, ["scan", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "pass"
    assert payload["summary"]["findings"] == 0
    assert payload["findings"] == []


def test_scan_help_does_not_error():
    runner = CliRunner()
    result = runner.invoke(cli.main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
    assert "--json" in result.output
    assert "--profile" in result.output


def test_main_help_lists_subcommands():
    runner = CliRunner()
    result = runner.invoke(cli.main, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
