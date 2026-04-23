from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path


def test_module_help_runs():
    """python -m keygate.cli --help should print help and exit 0."""
    result = subprocess.run(
        [sys.executable, "-m", "keygate.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "scan" in result.stdout


def test_console_script_entrypoint_is_declared():
    """The `keygate` console script should resolve to keygate.cli:main."""
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    assert data["project"]["scripts"]["keygate"] == "keygate.cli:main"
