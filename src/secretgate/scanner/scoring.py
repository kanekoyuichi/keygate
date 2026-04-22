from __future__ import annotations

import re

from secretgate.models import DiffLine, RuleMatch, ScanResult, Verdict

_TEST_FILE = re.compile(r"(?:^|/)test[s]?/|_test\.py$|test_.*\.py$", re.IGNORECASE)
_DUMMY_PATTERN = re.compile(r"\b(?:dummy|example)\b", re.IGNORECASE)


def _is_test_file(file_path: str) -> bool:
    return bool(_TEST_FILE.search(file_path))


def _contains_dummy_pattern(content: str) -> bool:
    return bool(_DUMMY_PATTERN.search(content))


def _build_reason(rule_matches: list[RuleMatch], entropy_score: int, context_score: int) -> str:
    parts: list[str] = []
    if rule_matches:
        parts.append(rule_matches[0].description)
    if entropy_score > 0:
        parts.append("high entropy string detected")
    if context_score > 0:
        parts.append("sensitive context detected")
    return "; ".join(parts) if parts else "suspicious pattern detected"


def aggregate(
    diff_line: DiffLine,
    rule_matches: list[RuleMatch],
    entropy_score: int,
    context_score: int,
    block_score: int = 70,
    warn_score: int = 40,
) -> ScanResult:
    breakdown: dict[str, int] = {}

    rule_score = 0
    if rule_matches:
        top = max(rule_matches, key=lambda m: m.score)
        rule_score = top.score
        breakdown[f"rule:{top.rule_id}"] = rule_score

    if entropy_score > 0:
        breakdown["entropy"] = entropy_score
    if context_score > 0:
        breakdown["context"] = context_score

    total = rule_score + entropy_score + context_score

    if _is_test_file(diff_line.file_path):
        breakdown["penalty:test_file"] = -10
        total -= 10
    if _contains_dummy_pattern(diff_line.content):
        breakdown["penalty:dummy"] = -20
        total -= 20

    total = max(0, total)

    if total >= block_score:
        verdict = Verdict.BLOCK
    elif total >= warn_score:
        verdict = Verdict.WARN
    else:
        verdict = Verdict.IGNORE

    return ScanResult(
        diff_line=diff_line,
        total_score=total,
        verdict=verdict,
        rule_matches=rule_matches,
        score_breakdown=breakdown,
        reason=_build_reason(rule_matches, entropy_score, context_score),
    )
