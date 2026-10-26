from __future__ import annotations

import re
import subprocess
from pathlib import Path

import click

from keygate.models import DiffLine

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_C_ESCAPE = re.compile(r"\\([0-7]{1,3}|.)")
_C_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v"}

# Forced so user config (diff.noprefix / diff.mnemonicPrefix / diff.dstPrefix)
# cannot change the "+++ b/" header shape the parser relies on.
_SRC_PREFIX = "a/"
_DST_PREFIX = "b/"


class DiffParseError(RuntimeError):
    """Raised when added lines appear before a recognizable file header.

    Scanning such a diff would silently skip lines, so the caller must fail closed.
    """


def get_repo_root(cwd: Path | None = None) -> Path:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            cwd=cwd,
        )
    except FileNotFoundError as e:
        raise click.ClickException("git is required but was not found in PATH.") from e
    if result.returncode != 0:
        raise click.ClickException("not a git repository")
    return Path(result.stdout.strip())


def get_staged_diff() -> str:
    try:
        check = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise click.ClickException("git is required but was not found in PATH.") from e
    if check.returncode != 0:
        raise click.ClickException("not a git repository")

    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.quotepath=false",
                "diff",
                "--cached",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                f"--src-prefix={_SRC_PREFIX}",
                f"--dst-prefix={_DST_PREFIX}",
            ],
            capture_output=True,
        )
    except FileNotFoundError as e:
        raise click.ClickException("git is required but was not found in PATH.") from e
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise click.ClickException(f"git diff failed: {stderr}")
    # Bytes are decoded here (not via text=True) so that line splitting below
    # follows git's "\n"-only boundaries and non-UTF-8 files cannot raise.
    return result.stdout.decode("utf-8", errors="replace")


def _unquote_c_style(quoted: str) -> str:
    # git quotes paths containing '"', '\', control characters, etc. as a
    # C string: "b/a\"b.env", "b/a\tb.env", "b/\343\201\202.py".
    body = quoted[1:-1] if quoted.endswith('"') else quoted[1:]
    # Octal escapes are raw bytes of a UTF-8 sequence, so collect everything
    # as bytes and decode once at the end.
    out = bytearray()
    pos = 0
    for m in _C_ESCAPE.finditer(body):
        out += body[pos:m.start()].encode("utf-8")
        esc = m.group(1)
        if esc.isdigit():
            out.append(int(esc, 8) & 0xFF)
        else:
            out += _C_SIMPLE_ESCAPES.get(esc, esc).encode("utf-8")
        pos = m.end()
    out += body[pos:].encode("utf-8")
    return out.decode("utf-8", errors="replace")


def _parse_target_path(header: str) -> str | None:
    # header is the text after "+++ ".
    target = header.split("\t", 1)[0] if not header.startswith('"') else header
    if target == "/dev/null":
        return None
    if target.startswith('"'):
        target = _unquote_c_style(target)
    if target.startswith(_DST_PREFIX):
        return target[len(_DST_PREFIX):]
    # Prefix is forced on the git command line; tolerate its absence anyway
    # rather than dropping every added line of the file.
    return target


def parse_diff(diff_output: str) -> list[DiffLine]:
    lines: list[DiffLine] = []
    current_file: str | None = None
    current_line = 0
    in_hunk = False

    # Split on "\n" only. str.splitlines() would also break on \r, \f, \v,
    # U+0085, U+2028 and U+2029, which git does not treat as line boundaries;
    # content after such a character would then be dropped from the scan.
    raw_lines = diff_output.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()

    for raw in raw_lines:
        if raw.startswith("diff "):
            in_hunk = False
            current_file = None
            continue

        if not in_hunk:
            if raw.startswith("+++ "):
                current_file = _parse_target_path(raw[4:])
            elif raw.startswith("@@"):
                m = _HUNK_HEADER.match(raw)
                if m:
                    current_line = int(m.group(1))
                    in_hunk = True
            # "--- ", "index ", "new file mode", "rename from", ... are ignored.
            continue

        # Inside a hunk: "+++ ..." / "--- ..." are content, not headers.
        if raw.startswith("@@"):
            m = _HUNK_HEADER.match(raw)
            if m:
                current_line = int(m.group(1))
            continue

        if raw.startswith("+"):
            if current_file is None:
                # Added lines can never target /dev/null, so the file header
                # was not understood. Fail closed instead of skipping them.
                raise DiffParseError(
                    "added lines appeared before a recognizable file header"
                )
            lines.append(DiffLine(
                file_path=current_file,
                line_number=current_line,
                content=raw[1:],
            ))
            current_line += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            # Removed line, or "\ No newline at end of file".
            pass
        else:
            current_line += 1

    return lines
