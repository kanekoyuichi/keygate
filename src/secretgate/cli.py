from __future__ import annotations

from pathlib import Path

import click

from secretgate.config import load_config
from secretgate.diff.parser import get_staged_diff, parse_diff
from secretgate.hook.installer import install
from secretgate.models import ScanResult, Verdict
from secretgate.policy import allowlist, baseline, inline
from secretgate.scanner import context, entropy, rules, scoring


def _print_result(result: ScanResult, level: str) -> None:
    headline = "High confidence secret detected" if level == "BLOCK" else "Potential secret detected"
    click.echo(f"\n[{level}] {headline}")
    click.echo(f"\nFile: {result.diff_line.file_path}:{result.diff_line.line_number}")
    if result.rule_matches:
        click.echo(f"Rule: {result.rule_matches[0].rule_id}")
    click.echo(f"Score: {result.total_score}")
    click.echo(f"\nReason:\n{result.reason}")
    if result.rule_matches and result.rule_matches[0].remediation:
        click.echo("\nRemediation:")
        for item in result.rule_matches[0].remediation:
            click.echo(f"  - {item}")
    click.echo('\nTo ignore:\n  Add comment: # secretgate: ignore reason="..."')


def _run_scan(repo_root: Path) -> tuple[list[ScanResult], list[ScanResult]]:
    cfg = load_config(repo_root)
    diff_output = get_staged_diff()
    diff_lines = parse_diff(diff_output)

    if not diff_lines:
        return [], []

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
        context_score = context.score_line(line.content, line.file_path)
        result = scoring.aggregate(
            line, rule_matches, entropy_score, context_score,
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

    return blocked, warned


@click.group()
def main() -> None:
    """secretgate - Git pre-commit secret scanner."""


@main.command()
def scan() -> None:
    """Scan staged diff for secrets."""
    repo_root = Path.cwd()
    blocked, warned = _run_scan(repo_root)

    for result in warned:
        _print_result(result, "WARN")

    for result in blocked:
        _print_result(result, "BLOCK")

    if blocked:
        raise SystemExit(1)


@main.command("install-hook")
def install_hook() -> None:
    """Install secretgate as a pre-commit hook."""
    install(Path.cwd())


@main.group(name="baseline")
def baseline_group() -> None:
    """Manage baseline fingerprints."""


@baseline_group.command("create")
def baseline_create() -> None:
    """Create baseline from current scan results."""
    repo_root = Path.cwd()
    cfg = load_config(repo_root)
    store = baseline.BaselineStore(repo_root / cfg.baseline_path)

    blocked, warned = _run_scan(repo_root)
    all_results = blocked + warned
    store.add_from_results(all_results)
    store.save()
    click.echo(f"Baseline created: {len(all_results)} finding(s) recorded.")


@baseline_group.command("update")
def baseline_update() -> None:
    """Update baseline with new findings."""
    repo_root = Path.cwd()
    cfg = load_config(repo_root)
    store = baseline.BaselineStore(repo_root / cfg.baseline_path)
    store.load()

    blocked, warned = _run_scan(repo_root)
    all_results = blocked + warned
    store.add_from_results(all_results)
    store.save()
    click.echo(f"Baseline updated: {len(all_results)} new finding(s) added.")
