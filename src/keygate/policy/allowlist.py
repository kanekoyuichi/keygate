from __future__ import annotations

import fnmatch

from keygate.models import DiffLine, PolicyResult


def check(diff_line: DiffLine, paths: list[str], patterns: list[str]) -> PolicyResult:
    for path_pattern in paths:
        if fnmatch.fnmatch(diff_line.file_path, path_pattern):
            return PolicyResult(suppressed=True, reason=f"allowlist:path:{path_pattern}")
    for pattern in patterns:
        if pattern in diff_line.content:
            return PolicyResult(suppressed=True, reason=f"allowlist:pattern:{pattern}")
    return PolicyResult(suppressed=False, reason=None)
