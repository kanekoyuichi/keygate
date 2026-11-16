from __future__ import annotations

from keygate.models import ScanReport, ScanResult

_RERUN_NOTICE = (
    "KeyGate detected secrets and blocked this commit.\n"
    "\n"
    "For machine-readable output, run:\n"
    "  keygate scan --format json"
)


def _format_finding(result: ScanResult, level: str) -> str:
    headline = (
        "High confidence secret detected"
        if level == "BLOCK"
        else "Potential secret detected"
    )
    lines: list[str] = []
    lines.append(f"\n[{level}] {headline}")
    lines.append("")
    lines.append(f"File: {result.diff_line.file_path}:{result.diff_line.line_number}")
    top = result.top_match
    if top is not None:
        lines.append(f"Rule: {top.rule_id}")
    lines.append(f"Score: {result.total_score}")
    lines.append("")
    lines.append("Reason:")
    lines.append(result.reason)
    if top is not None and top.remediation:
        lines.append("")
        lines.append("Remediation:")
        for item in top.remediation:
            lines.append(f"  - {item}")
    lines.append("")
    lines.append("To ignore:")
    lines.append('  Add comment: # keygate: ignore reason="..."')
    return "\n".join(lines)


def format(report: ScanReport) -> str:
    parts: list[str] = []
    parts.append(f"[KEYGATE] status={report.status} findings={report.summary.findings}")

    for result in report.blocked:
        parts.append(_format_finding(result, "BLOCK"))

    for result in report.warned:
        parts.append(_format_finding(result, "WARN"))

    if report.status == "block":
        parts.append("")
        parts.append(_RERUN_NOTICE)

    return "\n".join(parts)
