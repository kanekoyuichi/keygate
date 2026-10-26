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


def test_load_config_reads_utf8_with_non_ascii_comment(tmp_path):
    (tmp_path / "keygate.toml").write_bytes(
        "# 日本語コメント\n[scan]\nblock_score = 75\n".encode("utf-8")
    )
    assert load_config(tmp_path).block_score == 75


def test_load_config_raises_on_non_utf8_bytes(tmp_path):
    (tmp_path / "keygate.toml").write_bytes(b"# \xff\xfe\n[scan]\n")
    with pytest.raises(click.ClickException, match="keygate.toml"):
        load_config(tmp_path)


def test_load_config_allows_warn_score_equal_to_block_score(tmp_path):
    (tmp_path / "keygate.toml").write_text("[scan]\nblock_score = 60\nwarn_score = 60\n")
    cfg = load_config(tmp_path)
    assert cfg.warn_score == cfg.block_score == 60


def test_load_config_accepts_integer_entropy_threshold(tmp_path):
    (tmp_path / "keygate.toml").write_text("[scan]\nentropy_threshold = 4\n")
    assert load_config(tmp_path).entropy_threshold == 4


@pytest.mark.parametrize(
    ("toml", "message"),
    [
        ("[scan]\nblock_score = -1\n", "block_score"),
        ("[scan]\nwarn_score = 0\n", "warn_score"),
        ('[scan]\nblock_score = "70"\n', "block_score"),
        ("[scan]\nblock_score = true\n", "block_score"),
        ("[scan]\nblock_score = 70.5\n", "block_score"),
        ("[scan]\nwarn_score = 90\n", "warn_score .* <= block_score"),
        ("[scan]\nblock_score = 30\n", "warn_score .* <= block_score"),
        ("[scan]\nentropy_threshold = 0\n", "entropy_threshold"),
        ("[scan]\nentropy_threshold = -1.5\n", "entropy_threshold"),
        ("[scan]\nentropy_threshold = inf\n", "entropy_threshold"),
        ("[scan]\nentropy_threshold = nan\n", "entropy_threshold"),
        ('[scan]\nentropy_threshold = "high"\n', "entropy_threshold"),
        ("[scan]\nentropy_threshold = false\n", "entropy_threshold"),
        ('[allowlist]\npaths = "vendor/**"\n', r"\[allowlist\] paths"),
        ("[allowlist]\npatterns = [1, 2]\n", r"\[allowlist\] patterns"),
        ('[allowlist]\nkeywords = "fixture"\n', r"\[allowlist\] keywords"),
        ('[baseline]\npath = ""\n', r"\[baseline\] path"),
        ("[baseline]\npath = 1\n", r"\[baseline\] path"),
        ("scan = 1\n", r"\[scan\] must be a table"),
    ],
)
def test_load_config_rejects_invalid_values(tmp_path, toml, message):
    (tmp_path / "keygate.toml").write_text(toml)
    with pytest.raises(click.ClickException, match=message):
        load_config(tmp_path)
