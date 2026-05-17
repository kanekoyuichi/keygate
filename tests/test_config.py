from __future__ import annotations

import click
import pytest

from keygate.config import Config, load_config


def test_load_config_returns_defaults_when_no_toml(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg == Config()
    assert cfg.entropy_threshold == 4.2
    assert cfg.block_score == 70
    assert cfg.warn_score == 40
    assert cfg.baseline_path == ".keygate.baseline.json"
    assert cfg.allowlist_paths == []
    assert cfg.allowlist_patterns == []
    assert cfg.allowlist_keywords == []


def test_load_config_reads_all_fields(tmp_path):
    (tmp_path / "keygate.toml").write_text("""\
[scan]
entropy_threshold = 3.5
block_score = 80
warn_score = 50

[allowlist]
paths = ["vendor/**"]
patterns = ["EXAMPLE_KEY"]
keywords = ["placeholder"]

[baseline]
path = "custom.baseline.json"
""")
    cfg = load_config(tmp_path)
    assert cfg.entropy_threshold == 3.5
    assert cfg.block_score == 80
    assert cfg.warn_score == 50
    assert cfg.allowlist_paths == ["vendor/**"]
    assert cfg.allowlist_patterns == ["EXAMPLE_KEY"]
    assert cfg.allowlist_keywords == ["placeholder"]
    assert cfg.baseline_path == "custom.baseline.json"


def test_load_config_raises_on_invalid_toml(tmp_path):
    (tmp_path / "keygate.toml").write_text("this is not valid toml ][[[")
    with pytest.raises(click.ClickException, match="keygate.toml"):
        load_config(tmp_path)


def test_load_config_partial_toml_keeps_defaults(tmp_path):
    (tmp_path / "keygate.toml").write_text("[scan]\nblock_score = 60\n")
    cfg = load_config(tmp_path)
    assert cfg.block_score == 60
    assert cfg.warn_score == 40
    assert cfg.entropy_threshold == 4.2
    assert cfg.baseline_path == ".keygate.baseline.json"


def test_load_config_custom_baseline_path_is_used(tmp_path):
    (tmp_path / "keygate.toml").write_text('[baseline]\npath = "alt.json"\n')
    cfg = load_config(tmp_path)
    assert cfg.baseline_path == "alt.json"
