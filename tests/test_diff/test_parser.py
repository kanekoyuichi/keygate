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


def test_parse_non_ascii_file_path():
    # core.quotepath=false により非ASCIIパスは生のUTF-8でヘッダに現れる。
    # quotepath が有効だと "\346..." のように壊れるため、その状態を固定する。
    diff = """\
diff --git a/設定.py b/設定.py
index 0000000..1111111 100644
--- a/設定.py
+++ b/設定.py
@@ -1 +1,2 @@
+api_key = "secret"
"""
    lines = parse_diff(diff)
    assert len(lines) == 1
    assert lines[0].file_path == "設定.py"


def test_empty_diff():
    assert parse_diff("") == []


def test_get_staged_diff_without_git_raises(monkeypatch):
    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", raise_file_not_found)

    with pytest.raises(click.ClickException, match="git is required but was not found in PATH."):
        get_staged_diff()


ADDED_THEN_DELETED_DIFF = """\
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,1 @@
+added_line = 1
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1,1 +0,0 @@
-removed_line = 1
"""


def test_deleted_file_after_added_produces_no_diff_lines():
    lines = parse_diff(ADDED_THEN_DELETED_DIFF)
    assert len(lines) == 1
    assert lines[0].file_path == "new.py"
    assert lines[0].content == "added_line = 1"


def test_deleted_file_alone_produces_no_diff_lines():
    diff = """\
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1,1 +0,0 @@
-removed_line = 1
"""
    assert parse_diff(diff) == []


def test_added_line_starting_with_double_plus_is_parsed():
    diff = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1,2 @@
+++counter
"""
    lines = parse_diff(diff)
    assert len(lines) == 1
    assert lines[0].file_path == "app.py"
    assert lines[0].content == "++counter"


def test_get_staged_diff_uses_cached_unified_zero(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=b"" if "diff" in args else "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    get_staged_diff()

    assert calls[0] == ["git", "rev-parse", "--is-inside-work-tree"]
    assert calls[1] == [
        "git",
        "-c",
        "core.quotepath=false",
        "diff",
        "--cached",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--src-prefix=a/",
        "--dst-prefix=b/",
    ]
    # quotepath 無効化と色抑止は検知漏れ防止のため必須
    assert "core.quotepath=false" in calls[1]
    assert "--no-color" in calls[1]
    # prefix 固定は diff.noprefix / mnemonicPrefix による全行スキップ防止のため必須
    assert "--dst-prefix=b/" in calls[1]


def test_get_staged_diff_tolerates_non_utf8_bytes(monkeypatch):
    def fake_run(args, **kwargs):
        if "diff" in args:
            return subprocess.CompletedProcess(args, 0, stdout=b"+++ b/a.txt\n+\x82\xa0 key\n", stderr=b"")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    out = get_staged_diff()
    # Shift_JIS 等の非 UTF-8 バイトで内部エラーにせず、置換文字で読み進める
    assert isinstance(out, str)
    assert "\ufffd key" in out


def test_parse_noprefix_and_mnemonic_prefix_headers():
    # diff.noprefix=true では "+++ a.env"、mnemonicPrefix では "+++ i/a.env" になる。
    # コマンド側で prefix を固定しているが、パーサ単体でも行を落とさないこと。
    for header in ("+++ a.env", "+++ i/a.env"):
        diff = f"diff --git a.env a.env\n--- a.env\n{header}\n@@ -0,0 +1 @@\n+KEY=1\n"
        lines = parse_diff(diff)
        assert len(lines) == 1
        assert lines[0].content == "KEY=1"
    assert parse_diff(diff)[0].file_path == "i/a.env"


@pytest.mark.parametrize(
    ("quoted", "expected"),
    [
        ('"b/a\\"b.env"', 'a"b.env'),
        ('"b/a\\tb.env"', "a\tb.env"),
        ('"b/a\\\\b.env"', "a\\b.env"),
        ('"b/\\343\\201\\202.py"', "あ.py"),
    ],
)
def test_parse_c_quoted_file_path(quoted, expected):
    # git は '"', '\\', 制御文字を含むパスを C 文字列形式でクォートする
    diff = f"diff --git x x\n--- /dev/null\n+++ {quoted}\n@@ -0,0 +1 @@\n+KEY=1\n"
    lines = parse_diff(diff)
    assert len(lines) == 1
    assert lines[0].file_path == expected


@pytest.mark.parametrize("sep", ["\r", "\u2028", "\u2029", "\x85", "\x0c", "\x0b"])
def test_parse_keeps_content_after_non_newline_separators(sep):
    # git は "\n" のみを行境界とみなす。str.splitlines() の規則で分割すると
    # これらの文字以降の内容がスキャンから消える。
    diff = f"diff --git a/a.env b/a.env\n--- /dev/null\n+++ b/a.env\n@@ -0,0 +1 @@\n+x{sep}KEY=1\n"
    lines = parse_diff(diff)
    assert len(lines) == 1
    assert lines[0].content == f"x{sep}KEY=1"


def test_header_like_content_inside_hunk_is_treated_as_added_line():
    # ファイル内容の "++ /dev/null" や "++ b/docs/README.md" は diff 上では
    # "+++ ..." になるが、ハンク内ではヘッダではなく追加行として扱う。
    diff = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1,4 @@
+++ /dev/null
+++ b/docs/README.md
+KEY=1
"""
    lines = parse_diff(diff)
    assert [line.content for line in lines] == ["++ /dev/null", "++ b/docs/README.md", "KEY=1"]
    assert all(line.file_path == "app.py" for line in lines)


def test_added_line_without_file_header_fails_closed():
    from keygate.diff.parser import DiffParseError

    diff = "diff --git a/x b/x\n--- a/x\n+++ /dev/null\n@@ -1 +1 @@\n+KEY=1\n"
    with pytest.raises(DiffParseError):
        parse_diff(diff)


def test_no_newline_marker_does_not_shift_line_numbers():
    diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1,2 @@
+first = 1
\\ No newline at end of file
+second = 2
"""
    lines = parse_diff(diff)
    assert [(line.line_number, line.content) for line in lines] == [(1, "first = 1"), (2, "second = 2")]


def test_multiple_hunks_track_line_numbers():
    diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1,2 @@
+a = 1
@@ -10 +11,2 @@
 ctx = 0
+b = 2
"""
    lines = parse_diff(diff)
    assert [(line.line_number, line.content) for line in lines] == [(1, "a = 1"), (12, "b = 2")]


def test_get_repo_root_uses_git_toplevel(monkeypatch, tmp_path):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=str(tmp_path) + "\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert get_repo_root(tmp_path / "src") == tmp_path
    assert calls[0][0] == ["git", "rev-parse", "--show-toplevel"]
    assert calls[0][1]["cwd"] == tmp_path / "src"
