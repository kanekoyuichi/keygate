import pytest
import click

from secretgate.models import DiffLine
from secretgate.policy.inline import check


def make_line(content, file_path="app.py", line_number=1):
    return DiffLine(file_path=file_path, line_number=line_number, content=content)


def test_ignore_with_reason():
    line = make_line('key = "secret"  # secretgate: ignore reason="test data"')
    result = check(line)
    assert result.suppressed is True
    assert "test data" in result.reason


def test_no_ignore_comment():
    line = make_line('key = "secret"')
    result = check(line)
    assert result.suppressed is False


def test_ignore_without_reason_raises():
    line = make_line('key = "secret"  # secretgate: ignore')  # secretgate: ignore reason="test fixture for reason-less directive"
    with pytest.raises(click.ClickException):
        check(line)


def test_ignore_reason_included_in_policy_reason():
    line = make_line('x = 1  # secretgate: ignore reason="not a real key"')
    result = check(line)
    assert "not a real key" in result.reason
