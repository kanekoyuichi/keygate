import pytest
from keygate.scanner.context import ContextSignals, score_line


def test_no_signals():
    s = score_line("return 42", "app.py")
    assert s == ContextSignals()
    assert s.total == 0


# ---------- keyword tier ----------

@pytest.mark.parametrize("content", [
    'api_key = "x"',
    'API_KEY = "x"',
    'secret = "x"',
    'SECRET = "x"',
    'password = "x"',
    'passwd = "x"',
    'access_token = "x"',
    'access_key = "x"',
    'SECRET_KEY = "x"',
    'MY_PASSWORD = "x"',
    'private_key = "x"',
    'auth_token = "x"',
    'session_secret = "x"',
    'client_secret = "x"',
    'jwt_secret = "x"',
    'database_password = "x"',
    'db_password = "x"',
])
def test_high_tier_keyword(content):
    s = score_line(content, "app.py")
    assert s.keyword_tier == "high"
    assert s.keyword_score == 25


@pytest.mark.parametrize("content", [
    'token = "x"',
    'credential = "x"',
    'auth = "x"',
    'AUTH = "x"',
])
def test_mid_tier_keyword(content):
    s = score_line(content, "app.py")
    assert s.keyword_tier == "mid"
    assert s.keyword_score == 15


@pytest.mark.parametrize("content", [
    'user_id = "x"',
    'log_dir = "/var/log"',
    'total = price * qty',
    'author = "alice"',           # must not match 'auth'
    'authentic = True',           # must not match 'auth'
    'authorization_config = {}',  # must not match 'auth'
])
def test_no_keyword_match(content):
    s = score_line(content, "app.py")
    assert s.keyword_tier == ""
    assert s.keyword_score == 0


# ---------- path tier ----------

@pytest.mark.parametrize("path", [
    ".env",
    ".env.production",
    ".env.local",
    "apps/.env.staging",
])
def test_very_sensitive_path(path):
    s = score_line("x=1", path)
    assert s.path_score == 20


@pytest.mark.parametrize("path", [
    "settings.py",
    "app/settings/prod.py",
    "credentials.json",
    "credential.json",
    "secret.py",
    "secrets/main.py",
])
def test_sensitive_path(path):
    s = score_line("x=1", path)
    assert s.path_score == 15


@pytest.mark.parametrize("path", [
    "app.yaml",
    "compose.yml",
    "pyproject.toml",
    "database.ini",
    "app.properties",
])
def test_config_ext_path(path):
    s = score_line("x=1", path)
    assert s.path_score == 10


@pytest.mark.parametrize("path", ["app.py", "README.md", "main.go"])
def test_unremarkable_path(path):
    s = score_line("x=1", path)
    assert s.path_score == 0


# ---------- assignment ----------

@pytest.mark.parametrize("content", [
    'api_key = "x"',
    "api_key = 'x'",
    "api_key='x'",
    'password: "x"',
    "  password: 'x'",
    "export API_KEY=abc",
    "API_KEY=abc",
    "DB_URL: postgres://...",
])
def test_assignment_detected(content):
    s = score_line(content, "app.py")
    assert s.assignment_score == 15


@pytest.mark.parametrize("content", [
    'return "some string"',
    'if x == 1:',
    'logger.info("user %s", uid)',
    "# api_key = 'commented out'",
])
def test_assignment_not_detected(content):
    s = score_line(content, "app.py")
    assert s.assignment_score == 0


# ---------- total ----------

def test_total_sums_signals():
    s = score_line('SECRET_KEY = "x"', "settings.py")
    assert s.keyword_score == 25
    assert s.path_score == 15
    assert s.assignment_score == 15
    assert s.total == 55


def test_mixed_realistic_case():
    s = score_line('password: "ProdSecret"', "config.yaml")
    assert s.keyword_tier == "high"
    assert s.assignment_score == 15
    # config.yaml hits both sensitive substring "config" and yaml ext; sensitive wins (+15)
    assert s.path_score == 15


# ---------- regression: TN negatives ----------

def test_dummy_key_does_not_match_keyword():
    s = score_line('dummy_key = "x"', "test.py")
    assert s.keyword_tier == ""
    assert s.keyword_score == 0


def test_uuid_assignment_has_no_keyword():
    s = score_line('USER_ID = "550e8400-e29b-41d4-a716-446655440000"', "app.py")
    assert s.keyword_tier == ""
    assert s.assignment_score == 15


def test_error_message_string_no_keyword():
    s = score_line(
        'ERR = "InvalidRequestError: missing required parameter user_id"',
        "err.py",
    )
    assert s.keyword_tier == ""
