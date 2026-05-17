from __future__ import annotations

import json as _json
from typing import Any

from keygate.models import RuleMatch, ScanReport, ScanResult

SCHEMA_VERSION = "1"

_RECOMMENDED_ACTION_BY_RULE: dict[str, str] = {
    "aws-access-key": "move_to_secret_manager",
    "openai-api-key": "move_to_secret_manager",
    "anthropic-api-key": "move_to_secret_manager",
    "google-api-key": "move_to_secret_manager",
    "github-token": "move_to_secret_manager",
    "gitlab-token": "move_to_secret_manager",
    "slack-token": "move_to_secret_manager",
    "private-key-pem": "move_to_secret_manager",
    "stripe-secret-key": "move_to_secret_manager",
    "sendgrid-api-key": "move_to_secret_manager",
    "npm-token": "move_to_secret_manager",
    "pypi-token": "move_to_secret_manager",
    "django-secret-key": "move_to_secret_manager",
    "azure-connection-string": "move_to_secret_manager",
    "url-credentials": "remove_from_commit",
    "jwt": "manual_review",
    "stripe-publishable-key": "manual_review",
    "pii-email": "remove_from_commit",
    "pii-phone-jp": "remove_from_commit",
    "pii-credit-card": "remove_from_commit",
    "pii-ssn": "remove_from_commit",
    "pii-iban": "remove_from_commit",
    "pii-uk-nin": "remove_from_commit",
}


def _mask_snippet(matched_text: str) -> str | None:
    if not matched_text:
        return None
    length = len(matched_text)
    if length <= 8:
        return None
    head = matched_text[:4]
    tail = matched_text[-2:]
    return f"{head}***{tail}"


def _top_match(matches: list[RuleMatch]) -> RuleMatch | None:
    if not matches:
        return None
    return max(matches, key=lambda m: m.score)


def _finding_dict(result: ScanResult) -> dict[str, Any]:
    top = _top_match(result.rule_matches)
    finding: dict[str, Any] = {
        "rule_id": top.rule_id if top else None,
        "policy": top.policy if top else None,
        "score": result.total_score,
        "verdict": result.verdict.value,
        "file": result.diff_line.file_path,
        "line": result.diff_line.line_number,
        "message": result.reason,
        "recommended_action": (
            _RECOMMENDED_ACTION_BY_RULE.get(top.rule_id, "manual_review")
            if top
            else "manual_review"
        ),
    }
    if top is not None:
        snippet = _mask_snippet(top.matched_text)
        if snippet is not None:
            finding["snippet"] = snippet
    return finding


def build_report(report: ScanReport, scanned_lines: int | None = None) -> dict[str, Any]:
    summary_lines = scanned_lines if scanned_lines is not None else report.summary.scanned_lines
    return {
        "schema_version": SCHEMA_VERSION,
        "status": report.status,
        "summary": {
            "findings": report.summary.findings,
            "blocked": report.summary.blocked,
            "warned": report.summary.warned,
            "scanned_lines": summary_lines,
        },
        "findings": [
            _finding_dict(r) for r in (*report.blocked, *report.warned)
        ],
    }


def format(report: ScanReport) -> str:
    return _json.dumps(build_report(report), ensure_ascii=False, indent=2)
