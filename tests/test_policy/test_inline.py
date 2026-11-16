import pytest
import click

from keygate.models import DiffLine
from keygate.policy.inline import check


def make_line(content, file_path="app.py", line_number=1):
    return DiffLine(file_path=file_path, line_number=line_number, content=content)


def test_ignore_with_reason():
    line = make_line('key = "secret"  # keygate: ignore reason="test data"')
    result = check(line)
    assert result.suppressed is True
    assert "test data" in result.reason


def test_no_ignore_comment():
    line = make_line('key = "secret"')
    result = check(line)
    assert result.suppressed is False


def test_ignore_without_reason_raises():
    line = make_line('key = "secret"  # keygate: ignore')  # keygate: ignore reason="test fixture for reason-less directive"
    with pytest.raises(click.ClickException):
        check(line)


def test_ignore_reason_included_in_policy_reason():
    line = make_line('x = 1  # keygate: ignore reason="not a real key"')
    result = check(line)
    assert "not a real key" in result.reason


@pytest.mark.parametrize("content", [
    'const key = "secret";  // keygate: ignore reason="demo"',
    'key := "secret" /* keygate: ignore reason="demo" */',
    "SELECT 'secret';  -- keygate: ignore reason=\"demo\"",  # keygate: ignore reason="test fixture"
    '<code>secret</code> <!-- keygate: ignore reason="demo" -->',
])
def test_ignore_with_reason_in_other_comment_styles(content):
    result = check(make_line(content))
    assert result.suppressed is True
    assert result.reason == "inline:ignore:demo"


def test_ignore_without_reason_raises_for_slash_comment():
    line = make_line('const key = "secret";  // keygate: ignore')  # keygate: ignore reason="test fixture for reason-less directive"
    with pytest.raises(click.ClickException):
        check(line)


def test_directive_without_comment_marker_is_not_honored():
    assert check(make_line('msg = "keygate: ignore reason=\\"x\\""')).suppressed is False
