from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import click


@dataclass
class Config:
    entropy_threshold: float = 4.2
    block_score: int = 70
    warn_score: int = 40
    allowlist_paths: list[str] = field(default_factory=list)
    allowlist_patterns: list[str] = field(default_factory=list)
    allowlist_keywords: list[str] = field(default_factory=list)
    baseline_path: str = ".keygate.baseline.json"


def load_config(repo_root: Path) -> Config:
    config_path = repo_root / "keygate.toml"
    if not config_path.exists():
        return Config()
    try:
        data = tomllib.loads(config_path.read_text())
    except tomllib.TOMLDecodeError as e:
        raise click.ClickException(f"keygate.toml: {e}") from e

    scan = data.get("scan", {})
    allowlist = data.get("allowlist", {})
    baseline = data.get("baseline", {})

    return Config(
        entropy_threshold=scan.get("entropy_threshold", 4.2),
        block_score=scan.get("block_score", 70),
        warn_score=scan.get("warn_score", 40),
        allowlist_paths=allowlist.get("paths", []),
        allowlist_patterns=allowlist.get("patterns", []),
        allowlist_keywords=allowlist.get("keywords", []),
        baseline_path=baseline.get("path", ".keygate.baseline.json"),
    )
