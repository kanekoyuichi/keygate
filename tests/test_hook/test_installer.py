import subprocess
import sys

import click
import pytest

from keygate.hook.installer import install


@pytest.fixture
def git_repo(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    return tmp_path


def test_install_creates_hook(git_repo):
    install(git_repo)
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert "keygate scan" in hook.read_text()


def test_hook_is_executable(git_repo):
    install(git_repo)
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    assert hook.stat().st_mode & 0o111


def test_install_respects_core_hooks_path(git_repo):
    hooks_dir = git_repo / ".githooks"
    subprocess.run(
        ["git", "-C", str(git_repo), "config", "core.hooksPath", str(hooks_dir)],
        check=True,
        capture_output=True,
    )

    install(git_repo)

    hook = hooks_dir / "pre-commit"
    assert hook.exists()
    assert not (git_repo / ".git" / "hooks" / "pre-commit").exists()


def test_hook_uses_current_python_environment(git_repo):
    install(git_repo)
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    content = hook.read_text()
    assert f"{sys.executable} -m keygate.cli scan" in content
    assert "command -v keygate" in content


def test_install_outside_git_raises(tmp_path):
    with pytest.raises(click.ClickException):
        install(tmp_path)
