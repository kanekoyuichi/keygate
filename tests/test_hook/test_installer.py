import subprocess
import sys

import click
import pytest

from keygate.hook.installer import _build_hook_script, _to_posix_path, install, uninstall


@pytest.fixture
def git_repo(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    return tmp_path


def test_install_creates_hook(git_repo):
    install(git_repo)
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert "keygate scan" in hook.read_text()


@pytest.mark.skipif(sys.platform == "win32", reason="chmod is a no-op on Windows")
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
    expected_python = _to_posix_path(sys.executable)
    assert f"{expected_python} -m keygate.cli scan" in content
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


def test_install_preserves_existing_hook_as_backup(git_repo, monkeypatch):
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text("#!/bin/sh\necho original\n")
    hook.chmod(0o755)

    monkeypatch.setattr(click, "confirm", lambda *a, **kw: True)
    install(git_repo)

    backup = hook.parent / "pre-commit.keygate-orig"
    assert backup.read_text() == "#!/bin/sh\necho original\n"
    assert "keygate scan" in hook.read_text()
    assert "pre-commit.keygate-orig" in hook.read_text()


def test_install_existing_hook_confirm_abort_keeps_hook(git_repo, monkeypatch):
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text("#!/bin/sh\necho original\n")
    hook.chmod(0o755)

    monkeypatch.setattr(click, "confirm", lambda *a, **kw: (_ for _ in ()).throw(click.Abort()))
    with pytest.raises(click.Abort):
        install(git_repo)
    assert hook.read_text() == "#!/bin/sh\necho original\n"
    assert not (hook.parent / "pre-commit.keygate-orig").exists()


def test_install_over_own_hook_is_idempotent(git_repo, monkeypatch):
    install(git_repo)

    def fail_confirm(*a, **kw):
        raise AssertionError("confirm should not be called for keygate's own hook")

    monkeypatch.setattr(click, "confirm", fail_confirm)
    install(git_repo)

    hook = git_repo / ".git" / "hooks" / "pre-commit"
    assert "keygate scan" in hook.read_text()
    assert not (hook.parent / "pre-commit.keygate-orig").exists()


def test_install_refuses_to_overwrite_existing_backup(git_repo, monkeypatch):
    hooks_dir = git_repo / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    (hooks_dir / "pre-commit").write_text("#!/bin/sh\necho replaced manually\n")
    (hooks_dir / "pre-commit.keygate-orig").write_text("#!/bin/sh\necho old backup\n")

    monkeypatch.setattr(click, "confirm", lambda *a, **kw: True)
    with pytest.raises(click.ClickException, match="keygate-orig"):
        install(git_repo)


def test_uninstall_restores_backup(git_repo, monkeypatch):
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text("#!/bin/sh\necho original\n")
    hook.chmod(0o755)

    monkeypatch.setattr(click, "confirm", lambda *a, **kw: True)
    install(git_repo)
    uninstall(git_repo)

    assert hook.read_text() == "#!/bin/sh\necho original\n"
    assert not (hook.parent / "pre-commit.keygate-orig").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="requires sh")
def test_hook_runs_chained_hook_and_propagates_failure(git_repo, monkeypatch, tmp_path):
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(exist_ok=True)
    marker_file = tmp_path / "orig-ran"
    hook.write_text(f"#!/bin/sh\ntouch {marker_file}\nexit 7\n")
    hook.chmod(0o755)

    monkeypatch.setattr(click, "confirm", lambda *a, **kw: True)
    install(git_repo)

    result = subprocess.run(["sh", str(hook)], capture_output=True, cwd=git_repo)
    # 元フックが実行され、失敗コードがそのまま伝播する (keygate scan は走らない)
    assert marker_file.exists()
    assert result.returncode == 7


@pytest.mark.skipif(sys.platform == "win32", reason="requires sh")
def test_hook_runs_keygate_after_chained_hook_succeeds(git_repo, monkeypatch):
    hook = git_repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text("#!/bin/sh\nexit 0\n")
    hook.chmod(0o755)

    monkeypatch.setattr(click, "confirm", lambda *a, **kw: True)
    install(git_repo)

    result = subprocess.run(["sh", str(hook)], capture_output=True, text=True, cwd=git_repo)
    # 元フック成功後に keygate scan が実行される (ステージ差分なし -> pass)
    assert result.returncode == 0
    assert "status=pass" in result.stdout


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


def test_to_posix_path_passthrough_on_non_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert _to_posix_path("/usr/bin/python3") == "/usr/bin/python3"


def test_to_posix_path_converts_drive_path(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert _to_posix_path("C:\\Python311\\python.exe") == "/c/Python311/python.exe"


def test_to_posix_path_handles_spaces(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert _to_posix_path("C:\\Program Files\\Python311\\python.exe") == "/c/Program Files/Python311/python.exe"


def test_build_hook_script_uses_posix_path_on_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", "C:\\Python311\\python.exe")
    script = _build_hook_script()
    assert "/c/Python311/python.exe" in script
    assert "C:\\" not in script
