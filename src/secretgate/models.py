from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Verdict(enum.Enum):
    BLOCK = "block"
    WARN = "warn"
    IGNORE = "ignore"


@dataclass(frozen=True)
class DiffLine:
    file_path: str
    line_number: int
    content: str


@dataclass
class RuleMatch:
    rule_id: str
    matched_text: str
    score: int
    description: str
    remediation: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    diff_line: DiffLine
    total_score: int
    verdict: Verdict
    rule_matches: list[RuleMatch]
    score_breakdown: dict[str, int]
    reason: str


@dataclass
class PolicyResult:
    suppressed: bool
    reason: str | None
