import pytest
from keygate.scanner.rules import RULES, scan_line


@pytest.mark.parametrize("content,rule_id", [
    ("AWS_KEY=AKIAIOSFODNN7EXAMPLE1234", "aws-access-key"),
    ("key = sk-abcdefghijklmnopqrstuvwxyz123456", "openai-api-key"),
    ("key = sk-proj-" + "A" * 40, "openai-api-key"),  # keygate: ignore reason="test fixture"
    ("key = sk-svcacct-" + "A" * 40, "openai-api-key"),  # keygate: ignore reason="test fixture"
    ("token = ghp_" + "A" * 36, "github-token"),
    ("token = xoxb-EXAMPLEFAKETOKEN1234", "slack-token"),
    ("-----BEGIN RSA PRIVATE KEY-----", "private-key-pem"),
    ("token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "jwt"),
    ("key = sk_live_" + "A" * 24, "stripe-secret-key"),
    ("key = rk_live_" + "B" * 24, "stripe-secret-key"),
    ("key = pk_live_" + "C" * 24, "stripe-publishable-key"),
    ("key = SG." + "A" * 22 + "." + "B" * 43, "sendgrid-api-key"),
    ("DB = 'postgres://admin:s3cr3t@db.example.com/prod'", "url-credentials"),
    ("URL = 'https://user:pass@example.com'", "url-credentials"),
    ("REDIS = 'redis://user:xy9z@cache:6379'", "url-credentials"),
    ("key = sk-ant-api03-" + "A" * 95, "anthropic-api-key"),  # keygate: ignore reason="test fixture"
    ("key = AIza" + "A" * 35, "google-api-key"),  # keygate: ignore reason="test fixture"
    ("token = glpat-" + "A" * 20, "gitlab-token"),  # keygate: ignore reason="test fixture"
    ("token = npm_" + "A" * 36, "npm-token"),  # keygate: ignore reason="test fixture"
    ("token = pypi-" + "A" * 50, "pypi-token"),  # keygate: ignore reason="test fixture"
    ("SECRET_KEY = 'django-insecure-" + "a" * 50 + "'", "django-secret-key"),  # keygate: ignore reason="test fixture"
    ("conn = 'AccountKey=" + "A" * 86 + "==" + "'", "azure-connection-string"),  # keygate: ignore reason="test fixture"
    ("url = 'https://acct.blob.core.windows.net/c/blob?sv=2024-11-04&sp=r&sig=" + "A" * 32 + "'", "azure-sas-token"),  # keygate: ignore reason="test fixture"
    ("token = 'hf_" + "A" * 34 + "'", "huggingface-token"),  # keygate: ignore reason="test fixture"
    ("token = 'dckr_pat_" + "A" * 24 + "'", "dockerhub-token"),  # keygate: ignore reason="test fixture"
    ("VERCEL_TOKEN=" + "A" * 24, "vercel-token"),  # keygate: ignore reason="test fixture"
    ("SENTRY_DSN='https://" + "a" * 32 + "@sentry.example/123'", "sentry-dsn"),  # keygate: ignore reason="test fixture"
    ("DD_API_KEY=" + "a" * 32, "datadog-api-key"),  # keygate: ignore reason="test fixture"
    ("token = 'M" + "A" * 23 + "." + "B" * 6 + "." + "C" * 27 + "'", "discord-token"),  # keygate: ignore reason="test fixture"
    ("url = 'https://discord.com/api/webhooks/123456789012345678/" + "A" * 60 + "'", "discord-webhook-url"),  # keygate: ignore reason="test fixture"
    ("token = '123456789:" + "A" * 35 + "'", "telegram-bot-token"),  # keygate: ignore reason="test fixture"
    ("TWILIO_AUTH_TOKEN=" + "a" * 32, "twilio-auth-token"),  # keygate: ignore reason="test fixture"
    ("Authorization: Bearer " + "A" * 24, "authorization-bearer"),  # keygate: ignore reason="test fixture"
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "authorization-basic"),  # keygate: ignore reason="test fixture"
])
def test_rule_matches(content, rule_id):
    matches = scan_line(content)
    assert any(m.rule_id == rule_id for m in matches), f"Expected {rule_id} to match in: {content}"


def test_no_match_on_clean_line():
    assert scan_line("x = 42") == []


def test_rule_match_has_score():
    matches = scan_line("AKIAIOSFODNN7EXAMPLE1234")
    assert matches[0].score > 0


def test_rule_match_has_remediation():
    matches = scan_line("AKIAIOSFODNN7EXAMPLE1234")
    assert len(matches[0].remediation) > 0


def test_multiple_matches_for_same_rule_are_returned():
    matches = scan_line(
        "old=AKIAAAAAAAAAAAAAAAAA new=ASIABBBBBBBBBBBBBBBB"  # keygate: ignore reason="test fixture"
    )
    aws_matches = [m for m in matches if m.rule_id == "aws-access-key"]
    assert [m.matched_text for m in aws_matches] == [
        "AKIAAAAAAAAAAAAAAAAA",  # keygate: ignore reason="test fixture"
        "ASIABBBBBBBBBBBBBBBB",  # keygate: ignore reason="test fixture"
    ]


# ---------- Rule.policy classification ----------

def test_all_rules_have_policy():
    for rule in RULES:
        assert rule.policy in {"must_block", "public_exposable", "pii"}


def test_stripe_publishable_key_is_public_exposable():
    rule = next(r for r in RULES if r.rule_id == "stripe-publishable-key")
    assert rule.policy == "public_exposable"
    assert rule.score < 70


def test_stripe_secret_key_is_must_block():
    rule = next(r for r in RULES if r.rule_id == "stripe-secret-key")
    assert rule.policy == "must_block"
    assert rule.score >= 70


# ---------- URL credentials: real value ----------

def test_url_credentials_real_value_blocks():
    matches = scan_line("DB = 'postgres://admin:Sup3rSecr3t@host/prod'")
    m = next(x for x in matches if x.rule_id == "url-credentials")
    assert m.score == 70


# ---------- URL credentials: masked values are downgraded ----------

@pytest.mark.parametrize("masked", [
    "postgres://user:***@host/db",
    "postgres://user:****@host/db",
    "https://user:xxx@host/",
    "https://user:xxxx@host/",
    "mysql://user:REDACTED@host",
    "mysql://user:redacted@host",
    "postgres://user:...@host",
    "postgres://user:placeholder@host",
    "postgres://user:changeme@host",
    "postgres://user:your_password@host",
    "postgres://user:your-password@host",
    "postgres://user:<password>@host",
])
def test_url_credentials_masked_is_downgraded(masked):
    matches = scan_line(masked)
    m = next(x for x in matches if x.rule_id == "url-credentials")
    assert m.score == 40, f"Expected masked URL to be WARN-level: {masked}"


# ---------- False positive guards ----------

@pytest.mark.parametrize("content", [
    # UUID / hash
    '"550e8400-e29b-41d4-a716-446655440000"',
    '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
    # Semantic version
    '"1.2.3-rc.4+build.2026"',
    # Base64 image data URL (no URL credentials pattern)
    'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    # Dummy JWT-ish but broken
    "eyJnot-a-jwt-here",
    # .env.example style placeholder (no actual value)
    "API_KEY=your_api_key_here",
    # Comment line
    "# AWS_KEY = AKIA... (example only)",
    # Japanese text with 'secret' word nowhere
    "これはサンプルのメッセージで、秘密情報は含まれていません。",
    # CSS / HTML
    ".btn-primary.large.rounded { padding: 10px; }",
    '<div class="container" id="main-content"></div>',
    # Phone / IP / MAC
    '"+81-90-1234-5678"',
    '"2001:0db8:85a3:0000:0000:8a2e:0370:7334"',
    '"aa:bb:cc:dd:ee:ff"',
    # Filesystem path
    '"/var/log/app/production/access.log.2026-04-22"',
    # Function call
    'result = compute_hash(input_data, algorithm="sha256", salt=None)',
    # Error message string
    '"InvalidRequestError: missing required parameter user_id"',
    # Sha-prefixed short string (not OpenAI key)
    '"sk-short"',
    # Git SHA
    '"a1b2c3d4e5f6789012345678901234567890abcd"',
    # Short npm-like string (too short)
    '"npm_short"',
    # Short pypi-like string (too short)
    '"pypi-tooshort"',
    # Azure AccountKey without enough chars
    '"AccountKey=tooshort"',
    # Context-bound service tokens without enough structure
    '"hf_short"',
    '"vercel_token=short"',
    '"DD_API_KEY=nothexvalue"',
    '"Authorization: Bearer short"',
    '"Authorization: Basic bm90LWNvbG9u"',
])
def test_no_false_positive(content):
    matches = scan_line(content)
    secret_matches = [m for m in matches if m.policy != "pii"]
    assert secret_matches == [], f"Unexpected match on: {content} → {[m.rule_id for m in secret_matches]}"


# ---------- Specific rule-level negatives ----------

def test_openai_like_short_string_not_matched():
    assert scan_line('"sk-short"') == []


def test_anthropic_key_not_matched_as_openai():
    # sk-ant- は anthropic ルールのみが拾い、openai に二重マッチしないこと
    rule_ids = [
        m.rule_id
        for m in scan_line("key = sk-ant-api03-" + "A" * 95)  # keygate: ignore reason="test fixture"
    ]
    assert "anthropic-api-key" in rule_ids
    assert "openai-api-key" not in rule_ids


def test_fake_aws_prefix_not_matched():
    # AKIA prefix but too short
    assert scan_line("AKIA1234") == []


def test_url_without_credentials_not_matched():
    assert scan_line("URL = 'https://example.com/path?q=1'") == []


def test_url_with_port_only_not_matched():
    assert scan_line("URL = 'https://example.com:443/path'") == []


def test_basic_auth_without_colon_not_matched():
    assert scan_line("Authorization: Basic bm90LWNvbG9u") == []


def test_basic_auth_with_masked_password_not_matched():
    assert scan_line("Authorization: Basic dXNlcjoqKio=") == []


# ---------- PII rules ----------

@pytest.mark.parametrize("content,rule_id", [
    ('email = "user@example.com"', "pii-email"),  # keygate: ignore reason="test fixture"
    ('contact = "yamada@company.co.jp"', "pii-email"),  # keygate: ignore reason="test fixture"
    ('tel = "03-1234-5678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('mobile = "090-1234-5678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('intl = "+81-3-1234-5678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('mobile = "09012345678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('mobile = "08012345678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('mobile = "07012345678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('mobile = "05012345678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('tel = "(03)1234-5678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('tel = "03(1234)5678"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('tel = "03-1234-5678 ext123"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('tel = "03-1234-5678 ext. 123"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('tel = "03-1234-5678ext123"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('tel = "03-1234-5678 x123"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('tel = "03-1234-5678 内線123"', "pii-phone-jp"),  # keygate: ignore reason="test fixture"
    ('card = "4111111111111111"', "pii-credit-card"),  # keygate: ignore reason="test fixture"
    ('card = "4111-1111-1111-1111"', "pii-credit-card"),  # keygate: ignore reason="test fixture"
    ('card = "4111 1111 1111 1111"', "pii-credit-card"),  # keygate: ignore reason="test fixture"
    ('card = "5500005555555559"', "pii-credit-card"),  # keygate: ignore reason="test fixture"
    ('card = "5500-0055-5555-5559"', "pii-credit-card"),  # keygate: ignore reason="test fixture"
    ('card = "378282246310005"', "pii-credit-card"),  # keygate: ignore reason="test fixture"
    ('card = "3782-822463-10005"', "pii-credit-card"),  # keygate: ignore reason="test fixture"
    ('card = "3530111333300000"', "pii-credit-card"),  # keygate: ignore reason="test fixture" JCB
    ('card = "3530-1113-3330-0000"', "pii-credit-card"),  # keygate: ignore reason="test fixture" JCB
    ('ssn = "123-45-6789"', "pii-ssn"),  # keygate: ignore reason="test fixture"
    ('iban = "GB29NWBK60161331926819"', "pii-iban"),  # keygate: ignore reason="test fixture"
    ('iban = "GB29 NWBK 6016 1331 9268 19"', "pii-iban"),  # keygate: ignore reason="test fixture"
    ('iban = "gb29nwbk60161331926819"', "pii-iban"),  # keygate: ignore reason="test fixture" lowercase
    ('nin = "AB123456C"', "pii-uk-nin"),  # keygate: ignore reason="test fixture"
    ('nin = "AB 12 34 56 C"', "pii-uk-nin"),  # keygate: ignore reason="test fixture" spaced
])
def test_pii_rule_matches(content, rule_id):
    matches = scan_line(content)
    assert any(m.rule_id == rule_id for m in matches), \
        f"Expected {rule_id} to match in: {content}"


def test_uk_nin_not_detected_as_iban():
    matches = scan_line('nin = "AB123456C"')  # keygate: ignore reason="test fixture"
    rule_ids = [m.rule_id for m in matches]
    assert "pii-uk-nin" in rule_ids
    assert "pii-iban" not in rule_ids


def test_spaced_iban_not_detected_as_phone_jp():
    matches = scan_line('iban = "GB29 NWBK 6016 1331 9268 19"')  # keygate: ignore reason="test fixture"
    rule_ids = [m.rule_id for m in matches]
    assert "pii-iban" in rule_ids
    assert "pii-phone-jp" not in rule_ids


def test_pii_rules_have_pii_policy():
    pii_rules = [r for r in RULES if r.rule_id.startswith("pii-")]
    assert len(pii_rules) == 6
    for rule in pii_rules:
        assert rule.policy == "pii", f"{rule.rule_id} should have policy='pii'"


@pytest.mark.parametrize("content", [
    # Phone with extra trailing digit (partial-match guard)
    '"03-1234-56789"',
    '"090-1234-56789"',
    '"090123456789"',  # 12 digits (too long for no-sep mobile)
    # Phone with trailing letter (partial-match guard)
    '"03-1234-5678abc"',
    # SSN with invalid area (000)
    '"000-45-6789"',
    # SSN with invalid area (666)
    '"666-45-6789"',
    # SSN with invalid area (900+)
    '"900-45-6789"',
    # Too-short IBAN
    '"GB29NW"',
    # Non-IBAN country code uppercase identifier
    '"AB12CD34EF56GH78IJ90"',
    '"ZZ99XXXXXXXXXXXX"',
])
def test_pii_no_false_positive(content):
    pii_matches = [m for m in scan_line(content) if m.rule_id.startswith("pii-")]
    assert pii_matches == [], \
        f"Unexpected PII match on: {content} → {[m.rule_id for m in pii_matches]}"
