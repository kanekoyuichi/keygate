import subprocess
import sys

import click
import pytest

from keygate.hook.installer import install, uninstall


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


def test_install_without_git_raises(tmp_path, monkeypatch):
    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(subprocess, "run", raise_file_not_found)

    with pytest.raises(click.ClickException, match="git is required but was not found in PATH."):
        install(tmp_path)


def test_uninstall_removes_hook(git_repo):
    install(git_repo)
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    uninstall(git_repo)
    assert not hook.exists()


def test_uninstall_no_hook_does_not_raise(git_repo):
    uninstall(git_repo)


def test_uninstall_non_keygate_hook_requires_confirm(git_repo, monkeypatch):
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text("#!/bin/sh\necho hello\n")
    hook.chmod(0o755)

    monkeypatch.setattr(click, "confirm", lambda *a, **kw: (_ for _ in ()).throw(click.Abort()))
    with pytest.raises(click.Abort):
        uninstall(git_repo)
    assert hook.exists()


def test_uninstall_respects_core_hooks_path(git_repo):
    hooks_dir = git_repo / ".githooks"
    subprocess.run(
        ["git", "-C", str(git_repo), "config", "core.hooksPath", str(hooks_dir)],
        check=True,
        capture_output=True,
    )
    install(git_repo)
    hook = hooks_dir / "pre-commit"
    assert hook.exists()
    uninstall(git_repo)
    assert not hook.exists()
