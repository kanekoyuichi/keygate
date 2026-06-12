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


_MARKER = "# Installed by keygate"
_BACKUP_NAME = "pre-commit.keygate-orig"


def _build_hook_script() -> str:
    python_executable = shlex.quote(_to_posix_path(sys.executable))
    return f"""\
#!/bin/sh
{_MARKER}

# Run the pre-existing hook (saved by 'keygate activate') first.
hook_dir=$(dirname "$0")
if [ -x "$hook_dir/{_BACKUP_NAME}" ]; then
  "$hook_dir/{_BACKUP_NAME}" "$@" || exit $?
fi

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
    backup_path = hooks_dir / _BACKUP_NAME

    if hook_path.exists() and _MARKER not in hook_path.read_text():
        if backup_path.exists():
            raise click.ClickException(
                f"{backup_path} already exists. "
                f"Resolve it manually (restore or remove) before 'keygate activate'."
            )
        click.confirm(
            f"{hook_path} already exists. "
            f"Keep it as {_BACKUP_NAME} and run it before keygate?",
            abort=True,
        )
        hook_path.rename(backup_path)
        click.echo(f"Existing hook saved: {backup_path}")

    hook_path.write_text(_build_hook_script())
    hook_path.chmod(0o755)
    click.echo(f"Pre-commit hook enabled: {hook_path}")


def uninstall(repo_root: Path) -> None:
    hooks_dir = _resolve_hooks_dir(repo_root)
    hook_path = hooks_dir / "pre-commit"
    backup_path = hooks_dir / _BACKUP_NAME

    try:
        content = hook_path.read_text()
    except FileNotFoundError:
        click.echo("No pre-commit hook found.")
        return

    if _MARKER not in content:
        click.confirm(
            f"{hook_path} was not installed by keygate. Remove anyway?",
            abort=True,
        )

    hook_path.unlink()
    click.echo(f"Pre-commit hook disabled: {hook_path}")

    if backup_path.exists():
        backup_path.rename(hook_path)
        click.echo(f"Previous hook restored: {hook_path}")
