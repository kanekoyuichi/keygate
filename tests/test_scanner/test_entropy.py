import pytest

from keygate.scanner.entropy import calculate_shannon_entropy, scan_line


def test_high_entropy_string():
    # ランダムに見える長い文字列
    assert calculate_shannon_entropy("aB3xKp9mQzRvLwYnTjHcFsUeGdOiN2") > 4.0


def test_low_entropy_string():
    assert calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaa") < 1.0


def test_scan_line_detects_high_entropy():
    high_entropy = "aB3xKp9mQzRvLwYnTjHcFsUeGdOiN2Xb"
    assert scan_line(f'key = "{high_entropy}"') == 20


def test_scan_line_ignores_short_string():
    assert scan_line("key = aB3xKp9") == 0


def test_scan_line_ignores_low_entropy():
    assert scan_line("password = aaaaaaaaaaaaaaaaaaaaaaa") == 0


def test_scan_line_returns_20_even_with_multiple_tokens():
    high = "aB3xKp9mQzRvLwYnTjHcFsUeGdOiN2Xb"
    assert scan_line(f"{high} {high}") == 20


_HEX40 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"


def test_scan_line_detects_hex_secret():
    # hex は最大 4.0 bit/char なので、緩和なしでは閾値 4.2 に届かない
    assert calculate_shannon_entropy(_HEX40) < 4.2
    assert scan_line(f'SECRET_KEY = "{_HEX40}"') == 20
    assert scan_line(f"API_TOKEN={_HEX40.upper()}") == 20


@pytest.mark.parametrize("content", [
    f'commit_sha = "{_HEX40}"',
    f"digest: sha256:{_HEX40}",
    f'"integrity": "{_HEX40}"',
    f"checksum = {_HEX40}",
])
def test_scan_line_keeps_strict_threshold_for_hash_context(content):
    assert scan_line(content) == 0


def test_scan_line_ignores_short_or_mixed_case_hex():
    assert scan_line("key = a94a8fe5ccb19ba61c4c0873d391e98") == 0  # 31 chars
    assert scan_line("key = a94a8fe5CCB19BA61c4c0873d391e987") == 0
