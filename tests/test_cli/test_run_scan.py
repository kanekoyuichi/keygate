"""End-to-end tests for _run_scan pipeline: get_staged_diff → parse → scan → report.

get_staged_diff is patched so tests run without a real git repo.
"""
from __future__ import annotations

from keygate import cli
from keygate.policy.baseline import BaselineStore

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE1234"  # keygate: ignore reason="test fixture"
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
