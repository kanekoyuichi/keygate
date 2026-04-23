from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from keygate.models import DiffLine, PolicyResult, RuleMatch, ScanResult

_VERSION = 1


def _fingerprint(file_path: str, line_number: int, matched_text: str) -> str:
    data = f"{file_path}:{line_number}:{matched_text}"
    return hashlib.sha256(data.encode()).hexdigest()


class BaselineStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}

    def load(self) -> None:
        if not self._path.exists():
            return
        data = json.loads(self._path.read_text())
        self._entries = {e["fingerprint"]: e for e in data.get("entries", [])}

    def save(self) -> None:
        data = {
            "version": _VERSION,
            "entries": list(self._entries.values()),
        }
        self._path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def check(self, diff_line: DiffLine, rule_match: RuleMatch) -> PolicyResult:
        fp = _fingerprint(diff_line.file_path, diff_line.line_number, rule_match.matched_text)
        if fp in self._entries:
            return PolicyResult(suppressed=True, reason=f"baseline:{fp[:8]}")
        return PolicyResult(suppressed=False, reason=None)

    def add(self, diff_line: DiffLine, rule_match: RuleMatch) -> None:
        fp = _fingerprint(diff_line.file_path, diff_line.line_number, rule_match.matched_text)
        self._entries[fp] = {
            "fingerprint": fp,
            "file_path": diff_line.file_path,
            "line_number": diff_line.line_number,
            "rule_id": rule_match.rule_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def add_from_results(self, results: list[ScanResult]) -> None:
        for result in results:
            for match in result.rule_matches:
                self.add(result.diff_line, match)
