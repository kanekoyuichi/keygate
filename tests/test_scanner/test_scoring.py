import pytest
from secretgate.models import DiffLine, RuleMatch, Verdict
from secretgate.scanner.scoring import aggregate


def make_line(content="secret", file_path="app.py"):
    return DiffLine(file_path=file_path, line_number=1, content=content)


def make_rule_match(score=90):
    return RuleMatch(
        rule_id="aws-access-key",
        matched_text="AKIAIOSFODNN7EXAMPLE",
        score=score,
        description="AWS Access Key detected",
        remediation=["Rotate credentials"],
    )


def test_block_verdict():
    result = aggregate(make_line(), [make_rule_match(90)], 0, 0)
    assert result.verdict == Verdict.BLOCK
    assert result.total_score == 90


def test_warn_verdict():
    result = aggregate(make_line(), [make_rule_match(40)], 0, 0)
    assert result.verdict == Verdict.WARN


def test_ignore_verdict():
    result = aggregate(make_line(), [], 0, 0)
    assert result.verdict == Verdict.IGNORE
    assert result.total_score == 0


def test_only_top_rule_counted():
    matches = [make_rule_match(90), make_rule_match(80)]
    result = aggregate(make_line(), matches, 0, 0)
    assert result.total_score == 90


def test_test_file_penalty():
    line = make_line(file_path="tests/test_app.py")
    result = aggregate(line, [make_rule_match(75)], 0, 0)
    assert result.total_score == 65


def test_dummy_penalty():
    line = make_line(content="dummy key AKIAIOSFODNN7EXAMPLE")
    result = aggregate(line, [make_rule_match(75)], 0, 0)
    assert result.total_score == 55


def test_score_never_negative():
    line = make_line(content="dummy example placeholder", file_path="tests/test_app.py")
    result = aggregate(line, [], 0, 0)
    assert result.total_score == 0


def test_entropy_and_context_added():
    result = aggregate(make_line(), [], 20, 20)
    assert result.total_score == 40
    assert result.verdict == Verdict.WARN
