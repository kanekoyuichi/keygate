from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import click

from keygate.models import DiffLine, PolicyResult, RuleMatch, ScanResult

_VERSION = 1
_SYNTHETIC_RULE_ID = "context-entropy"


def _fingerprint(file_path: str, line_number: int, matched_text: str) -> str:
    data = f"{file_path}:{line_number}:{matched_text}"
    return hashlib.sha256(data.encode()).hexdigest()


def _synthetic_matched_text(diff_line: DiffLine) -> str:
    return f"{_SYNTHETIC_RULE_ID}:{diff_line.content}"


class BaselineStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}

    def load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            entries = data.get("entries", [])
            self._entries = {
                e["fingerprint"]: e
                for e in entries
                if isinstance(e, dict) and "fingerprint" in e
            }
        except (json.JSONDecodeError, OSError, AttributeError, TypeError) as e:
            click.echo(
                f"[KEYGATE] warning: ignoring unreadable baseline {self._path}: {e}",
                err=True,
            )
            self._entries = {}

    def save(self) -> None:
        data = {
            "version": _VERSION,
            "entries": list(self._entries.values()),
        }
        self._path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def count(self) -> int:
        return len(self._entries)

    def check(self, diff_line: DiffLine, rule_match: RuleMatch) -> PolicyResult:
        fp = _fingerprint(diff_line.file_path, diff_line.line_number, rule_match.matched_text)
        if fp in self._entries:
            return PolicyResult(suppressed=True, reason=f"baseline:{fp[:8]}")
        return PolicyResult(suppressed=False, reason=None)

    def check_result(self, result: ScanResult) -> PolicyResult:
        if result.rule_matches:
            suppressed = all(
                self.check(result.diff_line, match).suppressed
                for match in result.rule_matches
            )
            return PolicyResult(
                suppressed=suppressed,
                reason="baseline:all-rule-matches" if suppressed else None,
            )

        fp = _fingerprint(
            result.diff_line.file_path,
            result.diff_line.line_number,
            _synthetic_matched_text(result.diff_line),
        )
        if fp in self._entries:
            return PolicyResult(suppressed=True, reason=f"baseline:{fp[:8]}")
        return PolicyResult(suppressed=False, reason=None)

    def add(self, diff_line: DiffLine, rule_match: RuleMatch) -> bool:
        fp = _fingerprint(diff_line.file_path, diff_line.line_number, rule_match.matched_text)
        if fp in self._entries:
            return False
        self._entries[fp] = {
            "fingerprint": fp,
            "file_path": diff_line.file_path,
            "line_number": diff_line.line_number,
            "rule_id": rule_match.rule_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return True

    def add_result(self, result: ScanResult) -> int:
        if result.rule_matches:
            return sum(
                1 for match in result.rule_matches
                if self.add(result.diff_line, match)
            )

        fp = _fingerprint(
            result.diff_line.file_path,
            result.diff_line.line_number,
            _synthetic_matched_text(result.diff_line),
        )
        if fp in self._entries:
            return 0
        self._entries[fp] = {
            "fingerprint": fp,
            "file_path": result.diff_line.file_path,
            "line_number": result.diff_line.line_number,
            "rule_id": _SYNTHETIC_RULE_ID,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return 1

    def add_from_results(self, results: list[ScanResult]) -> int:
        added = 0
        for result in results:
            added += self.add_result(result)
        return added
