from __future__ import annotations

import subprocess
from pathlib import Path

import click

_HOOK_SCRIPT = """\
#!/bin/sh
# Installed by keygate
keygate scan
"""


def _find_git_dir(repo_root: Path) -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        capture_output=True,
        text=True,
        cwd=repo_root,
    )
    if result.returncode != 0:
        raise click.ClickException("Not a git repository.")
    return Path(result.stdout.strip())


def install(repo_root: Path) -> None:
    git_dir = _find_git_dir(repo_root)
    if not git_dir.is_absolute():
        git_dir = repo_root / git_dir

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        click.confirm(
            f"{hook_path} already exists. Overwrite?",
            abort=True,
        )

    hook_path.write_text(_HOOK_SCRIPT)
    hook_path.chmod(0o755)
    click.echo(f"Installed pre-commit hook: {hook_path}")
