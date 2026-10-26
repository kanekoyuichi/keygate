from __future__ import annotations

import math
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

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
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise click.ClickException(f"keygate.toml: {e}") from e

    scan = _section(data, "scan")
    allowlist = _section(data, "allowlist")
    baseline = _section(data, "baseline")

    cfg = Config(
        entropy_threshold=scan.get("entropy_threshold", 4.2),
        block_score=scan.get("block_score", 70),
        warn_score=scan.get("warn_score", 40),
        allowlist_paths=allowlist.get("paths", []),
        allowlist_patterns=allowlist.get("patterns", []),
        allowlist_keywords=allowlist.get("keywords", []),
        baseline_path=baseline.get("path", ".keygate.baseline.json"),
    )
    _validate(cfg)
    return cfg


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    section = data.get(name, {})
    if not isinstance(section, dict):
        _fail(f"[{name}]", "a table", section)
    return section


def _fail(key: str, requirement: str, value: object) -> NoReturn:
    raise click.ClickException(f"keygate.toml: {key} must be {requirement} (got {value!r})")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate(cfg: Config) -> None:
    for key, value in (("block_score", cfg.block_score), ("warn_score", cfg.warn_score)):
        if not _is_int(value) or value < 1:
            _fail(f"[scan] {key}", "an integer >= 1", value)
    if cfg.warn_score > cfg.block_score:
        raise click.ClickException(
            f"keygate.toml: [scan] warn_score ({cfg.warn_score}) must be "
            f"<= block_score ({cfg.block_score})"
        )

    threshold = cfg.entropy_threshold
    if (
        not (_is_int(threshold) or isinstance(threshold, float))
        or not math.isfinite(threshold)
        or threshold <= 0
    ):
        _fail("[scan] entropy_threshold", "a finite number > 0", threshold)

    for key, values in (
        ("paths", cfg.allowlist_paths),
        ("patterns", cfg.allowlist_patterns),
        ("keywords", cfg.allowlist_keywords),
    ):
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            _fail(f"[allowlist] {key}", "a list of strings", values)

    if not isinstance(cfg.baseline_path, str) or not cfg.baseline_path:
        _fail("[baseline] path", "a non-empty string", cfg.baseline_path)
