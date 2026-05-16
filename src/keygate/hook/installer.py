from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

import click


def _git_path(repo_root: Path, path_name: str) -> Path:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-path", path_name],
            capture_output=True,
            text=True,
            cwd=repo_root,
        )
    except FileNotFoundError as e:
        raise click.ClickException("git is required but was not found in PATH.") from e
    if result.returncode != 0:
        raise click.ClickException("Not a git repository.")
    return Path(result.stdout.strip())


def _to_posix_path(path: str) -> str:
    """Windows パスを MSYS2 POSIX 形式に変換する。非 Windows では素通し。"""
    if sys.platform != "win32":
        return path
    posix = path.replace("\\", "/")
    if len(posix) >= 2 and posix[1] == ":":
        return "/" + posix[0].lower() + posix[2:]
    return posix


def _build_hook_script() -> str:
    python_executable = shlex.quote(_to_posix_path(sys.executable))
    return f"""\
#!/bin/sh
# Installed by keygate

if [ -x {python_executable} ]; then
  exec {python_executable} -m keygate.cli scan
fi

if command -v keygate >/dev/null 2>&1; then
  exec keygate scan
fi

echo "keygate is not available. Reinstall it or update PATH." >&2
exit 1
"""


def _resolve_hooks_dir(repo_root: Path) -> Path:
    hooks_dir = _git_path(repo_root, "hooks")
    if not hooks_dir.is_absolute():
        hooks_dir = repo_root / hooks_dir
    return hooks_dir


def install(repo_root: Path) -> None:
    hooks_dir = _resolve_hooks_dir(repo_root)
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists():
        click.confirm(
            f"{hook_path} already exists. Overwrite?",
            abort=True,
        )

    hook_path.write_text(_build_hook_script())
    hook_path.chmod(0o755)
    click.echo(f"Pre-commit hook enabled: {hook_path}")


def uninstall(repo_root: Path) -> None:
    hooks_dir = _resolve_hooks_dir(repo_root)
    hook_path = hooks_dir / "pre-commit"

    try:
        content = hook_path.read_text()
    except FileNotFoundError:
        click.echo("No pre-commit hook found.")
        return

    if "# Installed by keygate" not in content:
        click.confirm(
            f"{hook_path} was not installed by keygate. Remove anyway?",
            abort=True,
        )

    hook_path.unlink()
    click.echo(f"Pre-commit hook disabled: {hook_path}")
