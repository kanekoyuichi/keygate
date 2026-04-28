from __future__ import annotations

from pathlib import Path

import click

from keygate.config import load_config
from keygate.diff.parser import get_staged_diff, parse_diff
from keygate.formatters import json as json_formatter
from keygate.formatters import text as text_formatter
from keygate.hook.installer import install
from keygate.models import ScanReport, ScanResult, ScanSummary, Status, Verdict
from keygate.policy import allowlist, baseline, inline
from keygate.scanner import context, entropy, rules, scoring


def _build_report(blocked: list[ScanResult], warned: list[ScanResult], scanned_lines: int) -> ScanReport:
    if blocked:
        status: Status = "block"
    elif warned:
        status = "warn"
    else:
        status = "pass"
    summary = ScanSummary(
        findings=len(blocked) + len(warned),
        blocked=len(blocked),
        warned=len(warned),
        scanned_lines=scanned_lines,
    )
    return ScanReport(status=status, summary=summary, blocked=blocked, warned=warned)


def _run_scan(repo_root: Path) -> ScanReport:
    cfg = load_config(repo_root)
    diff_output = get_staged_diff()
    diff_lines = parse_diff(diff_output)

    if not diff_lines:
        return _build_report([], [], 0)

    store = baseline.BaselineStore(repo_root / cfg.baseline_path)
    store.load()

    blocked: list[ScanResult] = []
    warned: list[ScanResult] = []

    for line in diff_lines:
        policy = inline.check(line)
        if policy.suppressed:
            continue

        policy = allowlist.check(line, cfg.allowlist_paths, cfg.allowlist_patterns)
        if policy.suppressed:
            continue

        rule_matches = rules.scan_line(line.content)
        entropy_score = entropy.scan_line(line.content, cfg.entropy_threshold)
        context_signals = context.score_line(line.content, line.file_path)
        result = scoring.aggregate(
            line, rule_matches, entropy_score, context_signals,
            cfg.block_score, cfg.warn_score,
        )

        if result.verdict == Verdict.IGNORE:
            continue

        if result.rule_matches and all(
            store.check(line, m).suppressed for m in result.rule_matches
        ):
            continue

        if result.verdict == Verdict.BLOCK:
            blocked.append(result)
        else:
            warned.append(result)

    return _build_report(blocked, warned, len(diff_lines))


def _resolve_format(format_opt: str | None, json_flag: bool, profile: str | None) -> str:
    """Resolve effective output format. Returns 'text' or 'json'.

    Raises click.UsageError on conflict (results in exit code 2).
    """
    requested: set[str] = set()
    if format_opt is not None:
        requested.add(format_opt)
    if json_flag:
        requested.add("json")
    if profile == "agent":
        requested.add("json")

    if len(requested) > 1:
        raise click.UsageError(
            "Conflicting output options: --format, --json, and --profile must agree."
        )
    if requested:
        return next(iter(requested))
    return "text"


@click.group(
    help=(
        "Block likely secrets before commit.\n\n"
        "By default, keygate scans added lines from 'git diff --cached' only.\n"
        "Use 'keygate scan --format json' for machine-readable output, or "
        "'keygate scan --profile agent' for AI-agent workflows.\n\n"
        "\b\n"
        "Examples:\n"
        "  keygate scan\n"
        "  keygate scan --format json\n"
        "  keygate install-hook\n"
        "  keygate baseline create"
    ),
)
@click.version_option("0.1.9", prog_name="keygate")
def main() -> None:
    """keygate - Git pre-commit secret scanner."""


@main.command(
    help=(
        "Scan staged additions for secrets.\n\n"
        "Scans added lines from 'git diff --cached' only.\n"
        "Default output is human-readable text.\n"
        "Use '--format json' or '--json' for JSON-only stdout.\n"
        "Use '--profile agent' to force JSON output for AI agents.\n\n"
        "Exit codes:\n"
        "  0  pass or warn\n"
        "  1  block\n"
        "  2  usage error\n\n"
        "\b\n"
        "Examples:\n"
        "  keygate scan\n"
        "  keygate scan --format json\n"
        "  keygate scan --json\n"
        "  keygate scan --profile agent"
    ),
)
@click.option(
    "--format",
    "format_opt",
    type=click.Choice(["text", "json"]),
    default=None,
    help="Output format. 'json' writes JSON only to stdout; default is text.",
)
@click.option(
    "--json",
    "json_flag",
    is_flag=True,
    default=False,
    help="Alias for '--format json'.",
)
@click.option(
    "--profile",
    type=click.Choice(["agent"]),
    default=None,
    help="Output profile. 'agent' forces JSON-only output for AI agents.",
)
def scan(format_opt: str | None, json_flag: bool, profile: str | None) -> None:
    """Scan staged diff for secrets."""
    output_format = _resolve_format(format_opt, json_flag, profile)

    repo_root = Path.cwd()
    report = _run_scan(repo_root)

    if output_format == "json":
        click.echo(json_formatter.format(report))
    else:
        click.echo(text_formatter.format(report))

    if report.status == "block":
        raise SystemExit(1)


@main.command(
    "install-hook",
    help=(
        "Install keygate as a Git pre-commit hook.\n\n"
        "The hook is installed into the hooks directory Git actually uses.\n"
        "If 'core.hooksPath' is configured, keygate installs there instead of "
        "forcing '.git/hooks'. The generated hook prefers the current Python "
        "environment and falls back to 'keygate scan' when needed.\n\n"
        "\b\n"
        "Example:\n"
        "  keygate install-hook"
    ),
)
def install_hook() -> None:
    """Install keygate as a pre-commit hook."""
    install(Path.cwd())


@main.group(
    name="baseline",
    help=(
        "Manage baseline fingerprints for accepted existing findings.\n\n"
        "Baselines let you ignore known findings and focus on newly added ones."
    ),
)
def baseline_group() -> None:
    """Manage baseline fingerprints."""


@baseline_group.command(
    "create",
    help=(
        "Create or extend the baseline from current findings.\n\n"
        "Existing baseline entries are preserved. Newly detected findings are "
        "added to '.keygate.baseline.json'. Use this when you want to accept "
        "current findings and focus on new ones going forward.\n\n"
        "\b\n"
        "Example:\n"
        "  keygate baseline create"
    ),
)
def baseline_create() -> None:
    """Create baseline from current scan results."""
    repo_root = Path.cwd()
    cfg = load_config(repo_root)
    store = baseline.BaselineStore(repo_root / cfg.baseline_path)
    store.load()

    report = _run_scan(repo_root)
    all_results = report.blocked + report.warned
    added = store.add_from_results(all_results)
    store.save()
    click.echo(
        f"Baseline created: {store.count()} total finding(s) recorded "
        f"({added} new)."
    )


@baseline_group.command(
    "update",
    help=(
        "Add newly detected findings to an existing baseline.\n\n"
        "Unlike an initial create flow, this command reports only the number of "
        "new fingerprints added.\n\n"
        "\b\n"
        "Example:\n"
        "  keygate baseline update"
    ),
)
def baseline_update() -> None:
    """Update baseline with new findings."""
    repo_root = Path.cwd()
    cfg = load_config(repo_root)
    store = baseline.BaselineStore(repo_root / cfg.baseline_path)
    store.load()

    report = _run_scan(repo_root)
    all_results = report.blocked + report.warned
    added = store.add_from_results(all_results)
    store.save()
    click.echo(f"Baseline updated: {added} new finding(s) added.")


if __name__ == "__main__":
    main()
