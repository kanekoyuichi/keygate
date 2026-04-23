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
