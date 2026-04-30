import subprocess

import click
import pytest

from keygate.diff.parser import get_repo_root, get_staged_diff, parse_diff

SAMPLE_DIFF = """\
diff --git a/config.py b/config.py
index 0000000..1111111 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,5 @@
 existing_line = 1
+api_key = "secret"
+another = "value"
 other_line = 2
"""

NEW_FILE_DIFF = """\
diff --git a/new.py b/new.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+line_one = 1
+line_two = 2
"""

MULTI_FILE_DIFF = """\
diff --git a/a.py b/a.py
index 0000000..1111111 100644
--- a/a.py
+++ b/a.py
@@ -1 +1,2 @@
+added_in_a = 1
diff --git a/b.py b/b.py
index 0000000..2222222 100644
--- a/b.py
+++ b/b.py
@@ -1 +1,2 @@
+added_in_b = 2
"""


def test_parse_added_lines():
    lines = parse_diff(SAMPLE_DIFF)
    assert len(lines) == 2
    assert lines[0].content == 'api_key = "secret"'
    assert lines[1].content == 'another = "value"'


def test_parse_file_path():
    lines = parse_diff(SAMPLE_DIFF)
    assert all(line.file_path == "config.py" for line in lines)


def test_parse_line_numbers():
    lines = parse_diff(SAMPLE_DIFF)
    assert lines[0].line_number == 2
    assert lines[1].line_number == 3


def test_parse_new_file():
    lines = parse_diff(NEW_FILE_DIFF)
    assert len(lines) == 2
    assert lines[0].line_number == 1
    assert lines[1].line_number == 2


def test_parse_multi_file():
    lines = parse_diff(MULTI_FILE_DIFF)
    assert len(lines) == 2
    assert lines[0].file_path == "a.py"
    assert lines[1].file_path == "b.py"


def test_empty_diff():
    assert parse_diff("") == []


def test_get_staged_diff_without_git_raises(monkeypatch):
    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", raise_file_not_found)

    with pytest.raises(click.ClickException, match="git is required but was not found in PATH."):
        get_staged_diff()


def test_get_repo_root_uses_git_toplevel(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=str(tmp_path) + "\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert get_repo_root(tmp_path / "src") == tmp_path
    assert calls[0][0] == ["git", "rev-parse", "--show-toplevel"]
    assert calls[0][1]["cwd"] == tmp_path / "src"
