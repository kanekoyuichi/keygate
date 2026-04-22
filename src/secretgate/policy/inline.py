from __future__ import annotations

import re

import click

from secretgate.models import DiffLine, PolicyResult

_IGNORE_WITH_REASON = re.compile(r"#\s*secretgate:\s*ignore\s+reason=\"(?P<reason>[^\"]+)\"")
_IGNORE_WITHOUT_REASON = re.compile(r"#\s*secretgate:\s*ignore\b")


def check(diff_line: DiffLine) -> PolicyResult:
    if m := _IGNORE_WITH_REASON.search(diff_line.content):
        return PolicyResult(suppressed=True, reason=f'inline:ignore:{m.group("reason")}')
    if _IGNORE_WITHOUT_REASON.search(diff_line.content):
        raise click.ClickException(
            f"{diff_line.file_path}:{diff_line.line_number}: "
            "'secretgate: ignore' requires a reason. "
            'Use: # secretgate: ignore reason="your reason here"'
        )
    return PolicyResult(suppressed=False, reason=None)
