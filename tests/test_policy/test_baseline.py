import json

from keygate.models import DiffLine, RuleMatch, ScanResult, Verdict
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


def make_result(line=None, matches=None):
    return ScanResult(
        diff_line=line or make_line(),
        total_score=90,
        verdict=Verdict.BLOCK,
        rule_matches=matches if matches is not None else [make_match()],
        score_breakdown={"entropy": 20},
        reason="sensitive context detected",
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


def test_add_from_results_records_context_entropy_finding(tmp_path):
    store = BaselineStore(tmp_path / "baseline.json")
    result = make_result(matches=[])

    assert store.add_from_results([result]) == 1
    assert store.add_from_results([result]) == 0
    assert store.check_result(result).suppressed is True


def test_check_result_requires_all_rule_matches_to_be_baselined(tmp_path):
    store = BaselineStore(tmp_path / "baseline.json")
    line = make_line()
    known = make_match("known-match-1")
    new = make_match("new-match-2")

    store.add(line, known)
    assert store.check_result(make_result(line=line, matches=[known, new])).suppressed is False

    store.add(line, new)
    assert store.check_result(make_result(line=line, matches=[known, new])).suppressed is True
