from __future__ import annotations

import re

from keygate.models import DiffLine, RuleMatch, ScanResult, Verdict
from keygate.scanner.context import ContextSignals

_TEST_FILE = re.compile(r"(?:^|/)test[s]?/|_test\.py$|test_.*\.py$", re.IGNORECASE)
_DUMMY_PATTERN = re.compile(r"\b(?:dummy|example)\b", re.IGNORECASE)
_PLACEHOLDER_PATH = re.compile(
    r"(?:^|/)(?:README(?:\.[^.]+)?|docs/|tests/fixtures/|[^/]*\.env\.example$|[^/]*\.example\.[^/]+$)",
    re.IGNORECASE,
)
_PLACEHOLDER_VALUE = re.compile(
    r"(?:"
    r"\b(?:dummy|example|changeme|replace[_-]?me|placeholder|redacted)\b"
    r"|<[^>]+>"
    r'|=\s*(?:""|\'\'|None)\s*(?:#.*)?$'
    r"|:\s*(?:\"\"|''|None)\s*(?:#.*)?$"
    r"|=\s*(?:#.*)?$"
    r")",
    re.IGNORECASE,
)
_COMMENT_SAMPLE_CONTEXT = re.compile(
    r"^\s*#|"
    r"\b(?:example only|sample|placeholder|documentation)\b",
    re.IGNORECASE,
)


def _is_test_file(file_path: str) -> bool:
    return bool(_TEST_FILE.search(file_path))


def _contains_dummy_pattern(content: str) -> bool:
    return bool(_DUMMY_PATTERN.search(content))


def _has_placeholder_path(file_path: str) -> bool:
    return bool(_PLACEHOLDER_PATH.search(file_path))


def _has_placeholder_value(content: str) -> bool:
    return bool(_PLACEHOLDER_VALUE.search(content))


def _has_comment_sample_context(content: str) -> bool:
    return bool(_COMMENT_SAMPLE_CONTEXT.search(content))


def _build_reason(
    rule_matches: list[RuleMatch],
    entropy_score: int,
    context_total: int,
) -> str:
    parts: list[str] = []
    if rule_matches:
        parts.append(rule_matches[0].description)
    if entropy_score > 0:
        parts.append("high entropy string detected")
    if context_total > 0:
        parts.append("sensitive context detected")
    return "; ".join(parts) if parts else "suspicious pattern detected"


def aggregate(
    diff_line: DiffLine,
    rule_matches: list[RuleMatch],
    entropy_score: int,
    context_signals: ContextSignals,
    block_score: int = 70,
    warn_score: int = 40,
) -> ScanResult:
    breakdown: dict[str, int] = {}

    top_match = max(rule_matches, key=lambda m: m.score) if rule_matches else None
    rule_score = top_match.score if top_match else 0
    if top_match is not None:
        breakdown[f"rule:{top_match.rule_id}"] = rule_score

    if entropy_score > 0:
        breakdown["entropy"] = entropy_score
    if context_signals.keyword_score > 0:
        breakdown[f"keyword:{context_signals.keyword_tier}"] = context_signals.keyword_score
    if context_signals.path_score > 0:
        breakdown["path"] = context_signals.path_score
    if context_signals.assignment_score > 0:
        breakdown["assignment"] = context_signals.assignment_score

    context_total = context_signals.total
    total = rule_score + entropy_score + context_total

    if not rule_matches:
        if context_signals.keyword_tier and entropy_score > 0:
            breakdown["combo:keyword+entropy"] = 15
            total += 15
        if (
            context_signals.keyword_tier == "high"
            and entropy_score > 0
            and context_signals.assignment_score > 0
        ):
            breakdown["combo:high+entropy+assignment"] = 15
            total += 15

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

    if verdict == Verdict.BLOCK and top_match is not None and top_match.policy == "pii":
        breakdown["cap:pii"] = warn_score
        total = min(total, warn_score)
        verdict = Verdict.WARN

    if (
        verdict == Verdict.BLOCK
        and top_match is not None
        and top_match.policy == "must_block"
        and _has_placeholder_value(diff_line.content)
        and (
            _has_placeholder_path(diff_line.file_path)
            or _has_comment_sample_context(diff_line.content)
        )
    ):
        breakdown["cap:placeholder_context"] = warn_score
        total = min(total, warn_score)
        verdict = Verdict.WARN

    return ScanResult(
        diff_line=diff_line,
        total_score=total,
        verdict=verdict,
        rule_matches=rule_matches,
        score_breakdown=breakdown,
        reason=_build_reason(rule_matches, entropy_score, context_total),
    )
