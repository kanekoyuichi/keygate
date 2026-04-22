from secretgate.scanner.context import score_line


def test_keyword_in_content():
    assert score_line("api_key = 'abc'", "app.py") == 20


def test_sensitive_file_path():
    assert score_line("x = 1", "config/settings.py") == 10


def test_url_with_auth():
    assert score_line("url = 'https://user:pass@example.com'", "app.py") == 20


def test_multiple_signals():
    score = score_line("password = 'secret'", ".env")
    assert score >= 30


def test_no_signals():
    assert score_line("x = 42", "app.py") == 0
