from __future__ import annotations

import fnmatch
import re

import click

from keygate.models import DiffLine, PolicyResult


def check(
    diff_line: DiffLine,
    paths: list[str],
    patterns: list[str],
    keywords: list[str] | None = None,
) -> PolicyResult:
    for path_pattern in paths:
        if fnmatch.fnmatch(diff_line.file_path, path_pattern):
            return PolicyResult(suppressed=True, reason=f"allowlist:path:{path_pattern}")
    for pattern in patterns:
        try:
            matched = re.search(pattern, diff_line.content) is not None
        except re.error as e:
            raise click.ClickException(
                f"invalid allowlist pattern {pattern!r}: {e}"
            ) from e
        if matched:
            return PolicyResult(suppressed=True, reason=f"allowlist:pattern:{pattern}")
    for keyword in keywords or []:
        if keyword.lower() in diff_line.content.lower():
            return PolicyResult(suppressed=True, reason=f"allowlist:keyword:{keyword}")
    return PolicyResult(suppressed=False, reason=None)
