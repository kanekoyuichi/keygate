"""End-to-end tests for _run_scan pipeline: get_staged_diff → parse → scan → report.

get_staged_diff is patched so tests run without a real git repo.
"""
from __future__ import annotations

from keygate import cli
from keygate.policy.baseline import BaselineStore

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # keygate: ignore reason="test fixture"
_AWS_DIFF = (
    "diff --git a/.env b/.env\n"
    "new file mode 100644\n"
    "--- /dev/null\n"
    "+++ b/.env\n"
    "@@ -0,0 +1 @@\n"
    f"+{_AWS_KEY}\n"  # keygate: ignore reason="test fixture"
)

_EMAIL_DIFF = (
    "diff --git a/app.py b/app.py\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1 +1,2 @@\n"
    '+email = "user@example.com"\n'  # keygate: ignore reason="test fixture"
)

_CLEAN_DIFF = (
    "diff --git a/app.py b/app.py\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1 +1,2 @@\n"
    "+x = 42\n"
)

_INLINE_IGNORE_DIFF = (
    "diff --git a/.env b/.env\n"
    "--- /dev/null\n"
    "+++ b/.env\n"
    "@@ -0,0 +1 @@\n"
    f'+{_AWS_KEY}  # keygate: ignore reason="test"\n'  # keygate: ignore reason="test fixture"
)


def test_run_scan_block(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _AWS_DIFF)
    report = cli._run_scan(tmp_path)
    assert report.status == "block"
    assert report.summary.blocked == 1
    assert report.summary.warned == 0


def test_run_scan_warn_pii_never_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _EMAIL_DIFF)
    report = cli._run_scan(tmp_path)
    assert report.status == "warn"
    assert report.summary.blocked == 0
    assert report.summary.warned == 1
    assert report.warned[0].verdict.value == "warn"


def test_run_scan_pass_on_clean_diff(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _CLEAN_DIFF)
    report = cli._run_scan(tmp_path)
    assert report.status == "pass"
    assert report.summary.findings == 0


def test_run_scan_inline_ignore_suppresses(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _INLINE_IGNORE_DIFF)
    report = cli._run_scan(tmp_path)
    assert report.status == "pass"
    assert report.summary.findings == 0


def test_run_scan_allowlist_keyword_suppresses(tmp_path, monkeypatch):
    (tmp_path / "keygate.toml").write_text(
        f'[allowlist]\nkeywords = ["{_AWS_KEY}"]\n'  # keygate: ignore reason="test fixture"
    )
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _AWS_DIFF)
    report = cli._run_scan(tmp_path)
    assert report.status == "pass"


def test_run_scan_allowlist_path_suppresses(tmp_path, monkeypatch):
    (tmp_path / "keygate.toml").write_text('[allowlist]\npaths = [".env"]\n')
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _AWS_DIFF)
    report = cli._run_scan(tmp_path)
    assert report.status == "pass"


def test_run_scan_baseline_suppresses_known_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _AWS_DIFF)

    # First scan: captures the block
    report1 = cli._run_scan(tmp_path)
    assert report1.status == "block"

    # Persist to baseline
    store = BaselineStore(tmp_path / ".keygate.baseline.json")
    store.load()
    store.add_from_results(report1.blocked + report1.warned)
    store.save()

    # Second scan: suppressed by baseline
    report2 = cli._run_scan(tmp_path)
    assert report2.status == "pass"


def test_run_scan_custom_block_score_from_config(tmp_path, monkeypatch):
    # AWS key in .env scores 110 (rule:90 + path:20).
    # block_score=115 → WARN instead of BLOCK.
    (tmp_path / "keygate.toml").write_text("[scan]\nblock_score = 115\n")
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _AWS_DIFF)
    report = cli._run_scan(tmp_path)
    assert report.status == "warn"
    assert report.summary.blocked == 0


# ---------- P1-9: text / JSON / reason agree on the representative rule ----------

_MULTI_RULE_DIFF = (
    "diff --git a/app.env b/app.env\n"
    "--- /dev/null\n"
    "+++ b/app.env\n"
    "@@ -0,0 +1 @@\n"
    "+DB=https://u:sk-ant-api03-" + "A" * 95 + "@h/x\n"  # keygate: ignore reason="test fixture"
)


def test_text_and_json_report_the_same_top_rule(tmp_path, monkeypatch):
    import json

    from keygate.formatters import json as json_formatter
    from keygate.formatters import text as text_formatter

    monkeypatch.setattr(cli, "get_staged_diff", lambda: _MULTI_RULE_DIFF)
    report = cli._run_scan(tmp_path)
    result = report.blocked[0]
    assert {m.rule_id for m in result.rule_matches} >= {"url-credentials", "anthropic-api-key"}
    assert result.top_match is not None
    assert result.top_match.rule_id == "anthropic-api-key"
    assert result.reason.startswith("Anthropic API Key detected")
    assert "Rule: anthropic-api-key" in text_formatter.format(report)
    finding = json.loads(json_formatter.format(report))["findings"][0]
    assert finding["rule_id"] == "anthropic-api-key"


# ---------- P1-10: binary files that git did not diff ----------

def _binary_diff(path: str) -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        "index 0000000..1234567\n"
        f"Binary files /dev/null and b/{path} differ\n"
    )


def test_binary_non_media_file_emits_notice(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _binary_diff("secrets.env") + _CLEAN_DIFF)
    report = cli._run_scan(tmp_path)
    assert report.status == "pass"
    err = capsys.readouterr().err
    assert "[KEYGATE] notice: not scanned (binary in git diff): secrets.env" in err


def test_binary_media_file_is_silent(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "get_staged_diff", lambda: _binary_diff("assets/logo.PNG"))
    report = cli._run_scan(tmp_path)
    assert report.status == "pass"
    assert capsys.readouterr().err == ""
