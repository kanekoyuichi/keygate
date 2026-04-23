import json
from pathlib import Path

import pytest

from keygate.models import DiffLine, RuleMatch
from keygate.policy.baseline import BaselineStore, _fingerprint


def make_line(file_path="app.py", line_number=1, content="secret"):
    return DiffLine(file_path=file_path, line_number=line_number, content=content)


def make_match(matched_text="AKIAIOSFODNN7EXAMPLE", rule_id="aws-access-key"):
    return RuleMatch(
        rule_id=rule_id,
        matched_text=matched_text,
        score=90,
        description="AWS key",
        remediation=[],
    )


def test_fingerprint_is_idempotent():
    fp1 = _fingerprint("app.py", 1, "secret")
    fp2 = _fingerprint("app.py", 1, "secret")
    assert fp1 == fp2


def test_fingerprint_differs_by_input():
    assert _fingerprint("a.py", 1, "x") != _fingerprint("b.py", 1, "x")
    assert _fingerprint("a.py", 1, "x") != _fingerprint("a.py", 2, "x")
    assert _fingerprint("a.py", 1, "x") != _fingerprint("a.py", 1, "y")


def test_check_suppresses_known_finding(tmp_path):
    store = BaselineStore(tmp_path / "baseline.json")
    line, match = make_line(), make_match()
    store.add(line, match)
    result = store.check(line, match)
    assert result.suppressed is True


def test_check_allows_unknown_finding(tmp_path):
    store = BaselineStore(tmp_path / "baseline.json")
    result = store.check(make_line(), make_match())
    assert result.suppressed is False


def test_save_and_load(tmp_path):
    path = tmp_path / "baseline.json"
    store = BaselineStore(path)
    store.add(make_line(), make_match())
    store.save()

    store2 = BaselineStore(path)
    store2.load()
    assert store2.check(make_line(), make_match()).suppressed is True


def test_load_nonexistent_file(tmp_path):
    store = BaselineStore(tmp_path / "nonexistent.json")
    store.load()  # エラーにならないこと
    assert store.check(make_line(), make_match()).suppressed is False


def test_saved_json_structure(tmp_path):
    path = tmp_path / "baseline.json"
    store = BaselineStore(path)
    store.add(make_line(), make_match())
    store.save()

    data = json.loads(path.read_text())
    assert data["version"] == 1
    assert len(data["entries"]) == 1
    entry = data["entries"][0]
    assert "fingerprint" in entry
    assert "file_path" in entry
    assert "line_number" in entry
    assert "rule_id" in entry
    assert "created_at" in entry
