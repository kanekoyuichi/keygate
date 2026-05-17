from __future__ import annotations

import re
import subprocess
from pathlib import Path

import click

from keygate.models import DiffLine

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


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
            ["git", "diff", "--cached", "--unified=0"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise click.ClickException("git is required but was not found in PATH.") from e
    if result.returncode != 0:
        raise click.ClickException(f"git diff failed: {result.stderr.strip()}")
    return result.stdout


def parse_diff(diff_output: str) -> list[DiffLine]:
    lines: list[DiffLine] = []
    current_file: str | None = None
    current_line = 0

    for raw in diff_output.splitlines():
        if raw.startswith("+++ b/"):
            current_file = raw[6:]
            continue

        if raw == "+++ /dev/null":
            current_file = None
            continue

        if raw.startswith("@@"):
            m = _HUNK_HEADER.match(raw)
            if m:
                current_line = int(m.group(1))
            continue

        if raw.startswith("---") or raw.startswith("diff ") or raw.startswith("index "):
            continue

        if raw.startswith("+"):
            if current_file is not None:
                lines.append(DiffLine(
                    file_path=current_file,
                    line_number=current_line,
                    content=raw[1:],
                ))
            current_line += 1
        elif raw.startswith("-"):
            pass
        else:
            current_line += 1

    return lines
