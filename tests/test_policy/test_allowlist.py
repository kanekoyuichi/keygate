from keygate.models import DiffLine
from keygate.policy.allowlist import check
import click
import pytest


def make_line(content="secret", file_path="app.py"):
    return DiffLine(file_path=file_path, line_number=1, content=content)


def test_path_allowlist_matches():
    line = make_line(file_path="tests/test_app.py")
    result = check(line, paths=["tests/*"], patterns=[])
    assert result.suppressed is True
    assert "allowlist:path" in result.reason


def test_pattern_allowlist_matches():
    line = make_line(content='key = "dummy-key"')
    result = check(line, paths=[], patterns=["dummy"])
    assert result.suppressed is True
    assert "allowlist:pattern" in result.reason


def test_pattern_allowlist_uses_regex():
    line = make_line(content="token = abc123")
    result = check(line, paths=[], patterns=[r"token\s*="])
    assert result.suppressed is True
    assert "allowlist:pattern" in result.reason


def test_invalid_pattern_raises_click_exception():
    line = make_line(content="token = abc123")
    with pytest.raises(click.ClickException, match="invalid allowlist pattern"):
        check(line, paths=[], patterns=["["])


def test_keyword_allowlist_matches_case_insensitive():
    line = make_line(content='api_key = "fixture-value"')
    result = check(line, paths=[], patterns=[], keywords=["FIXTURE"])
    assert result.suppressed is True
    assert "allowlist:keyword" in result.reason


def test_no_match():
    line = make_line(content='key = "real-secret"', file_path="src/app.py")
    result = check(line, paths=["tests/*"], patterns=["dummy"])
    assert result.suppressed is False


def test_wildcard_path():
    line = make_line(file_path="docs/example.md")
    result = check(line, paths=["docs/*"], patterns=[])
    assert result.suppressed is True
