import subprocess

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


def test_install_outside_git_raises(tmp_path):
    with pytest.raises(click.ClickException):
        install(tmp_path)
