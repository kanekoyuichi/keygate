"""
Precision/recall benchmark against a labeled corpus of known secrets and non-secrets.

Run as a pytest test (enforces thresholds) or directly for a detailed report:
    pytest tests/benchmark/benchmark.py -v
    python -m tests.benchmark.benchmark
"""
from __future__ import annotations

import dataclasses
from typing import Literal

from keygate.models import DiffLine, Verdict
from keygate.scanner.context import score_line as analyze
from keygate.scanner.entropy import scan_line as entropy_scan
from keygate.scanner.rules import scan_line as rules_scan
from keygate.scanner.scoring import aggregate

Label = Literal["secret", "benign"]


@dataclasses.dataclass(frozen=True)
class Sample:
    content: str
    label: Label
    file_path: str = "app.py"
    description: str = ""


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

CORPUS: list[Sample] = [
    # --- True Positives: rule-based secrets ---
    Sample("AKIAIOSFODNN7EXAMPLE", "secret", description="AWS AKIA access key"),
    Sample("ASIAIOSFODNN7ABCDEF01", "secret", description="AWS ASIA session key"),
    Sample("AROAIOSFODNN7ABCDEF01", "secret", description="AWS AROA role key"),
    Sample("sk-abcdefghijklmnopqrstuvwxyz123456", "secret", description="OpenAI API key"),
    Sample("ghp_" + "A" * 36, "secret", description="GitHub PAT (ghp_)"),
    Sample("github_pat_" + "A" * 82, "secret", description="GitHub fine-grained PAT"),
    Sample("xox" "b-123456789012-123456789012-abcdefghijklmnopqrs", "secret", description="Slack bot token"),
    Sample("xox" "p-123456789012-123456789012-abcdefghijklmnopqrs", "secret", description="Slack user token"),
    Sample("-----BEGIN RSA PRIVATE KEY-----", "secret", description="RSA private key PEM header"),
    Sample("-----BEGIN EC PRIVATE KEY-----", "secret", description="EC private key PEM header"),
    Sample("-----BEGIN OPENSSH PRIVATE KEY-----", "secret", description="OpenSSH private key PEM header"),
    Sample(
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "secret",
        description="JWT token",
    ),
    Sample("sk_live_" + "A" * 24, "secret", description="Stripe live secret key"),
    Sample("rk_live_" + "A" * 24, "secret", description="Stripe live restricted key"),
    Sample("SG." + "A" * 22 + "." + "B" * 43, "secret", description="SendGrid API key"),
    Sample("postgres://admin:s3cr3t@db.example.com/mydb", "secret", description="PostgreSQL URL with credentials"),
    Sample("mysql://root:passw0rd@localhost:3306/app", "secret", description="MySQL URL with credentials"),
    Sample("redis://:mypassword@cache.internal:6379/0", "secret", description="Redis URL with credentials (empty username)"),
    Sample("https://user:hunter2@internal.example.com/api", "secret", description="HTTPS URL with credentials"),
    Sample("mongodb://dbuser:Passw0rd!@mongo.example.com:27017/db", "secret", description="MongoDB URL with credentials"),
    Sample("ftp://deploy:S3cretPass@files.example.com/releases", "secret", description="FTP URL with credentials"),
    Sample("amqp://worker:RabbitPass9@mq.internal:5672/vhost", "secret", description="AMQP URL with credentials"),
    Sample("https://admin:Sup3rSecr3t@dashboard.internal/login", "secret", description="Admin URL with credentials"),
    Sample("sk-" + "A" * 48, "secret", description="OpenAI API key uppercase payload"),
    Sample("sk-" + "0123456789abcdef" * 3, "secret", description="OpenAI API key hex-like payload"),
    Sample("ghp_" + "B" * 36, "secret", description="GitHub PAT second sample"),
    Sample("github_pat_" + "B" * 82, "secret", description="GitHub fine-grained PAT second sample"),
    Sample("xox" "a-2-123456789012-123456789012-abcdefghijklmnopqrs", "secret", description="Slack app token"),
    Sample("xox" "r-123456789012-abcdefghijklmnopqrs", "secret", description="Slack refresh token"),
    Sample("sk_live_" + "B" * 32, "secret", description="Stripe live secret key long payload"),
    Sample("rk_live_" + "C" * 32, "secret", description="Stripe restricted live key long payload"),
    Sample("SG." + "C" * 22 + "." + "D" * 43, "secret", description="SendGrid API key second sample"),
    Sample("-----BEGIN PRIVATE KEY-----", "secret", description="PKCS8 private key PEM header"),
    # --- True Positives: context-based (no rule match) ---
    Sample(
        'api_key = "x8fa2dKq9Lm3Wn5Pqv7Zb4Cj6Hs0Ue1Xi"',
        "secret",
        file_path=".env",
        description="High-entropy value with api_key keyword in .env",
    ),
    Sample(
        'SECRET_KEY = "Kp3mQzRvLwYnTjH9cFsUeGdOiN2XbA8f"',
        "secret",
        file_path="settings.py",
        description="High-entropy value with SECRET_KEY in settings file",
    ),
    Sample(
        'password = "aB3xKp9mQzRvLwYnTjHcFsUeGdOiN2Xb"',
        "secret",
        description="High-entropy value with password keyword",
    ),
    Sample(
        'access_token = "Zx9Kp2Lq7Mn4Vb8Rw3Cd6Sf1Gh5Jk0Np"',
        "secret",
        description="High-entropy value with access_token keyword",
    ),
    Sample(
        'secret_token = "mN8vB3xQ7rT2yP9wL4kH6sD1fG5jC0zA"',
        "secret",
        description="High-entropy value with secret_token keyword",
    ),
    Sample(
        'client_secret = "cS9kLm2Pq7vWx4Za8Rn5Td0Hg3Jb6Fy1"',
        "secret",
        description="High-entropy value with client_secret keyword",
    ),
    Sample(
        'private_key = "pK8rVm3Tq1Wx9Za4Bn7Cd2Fg6Hs0Lj5Ne"',
        "secret",
        description="High-entropy value with private_key keyword",
    ),
    Sample(
        'database_password = "Db9xKp2Lm7Qv4Rn8Tz5Yw1Fc6Gh3Js0"',
        "secret",
        file_path="config/database.yaml",
        description="High-entropy database_password in config path",
    ),
    Sample(
        'DB_PASSWORD="Db3Lm9Qv7Wx2Za5Rn8Tf1Gh6Jk0Cd4"',
        "secret",
        file_path=".env.production",
        description="High-entropy DB_PASSWORD in production env",
    ),
    Sample(
        'SESSION_SECRET="Ss9Lm2Qv7Wx4Za8Rn5Tf1Gh6Jk0Cd3"',
        "secret",
        file_path=".env.local",
        description="High-entropy SESSION_SECRET in local env",
    ),
    Sample(
        'jwt_secret: "Jw8Lm2Qv7Wx4Za9Rn5Tf1Gh6Kp0Cd3"',
        "secret",
        file_path="settings/secrets.yaml",
        description="High-entropy jwt_secret in settings path",
    ),
    Sample(
        'export AUTH_TOKEN=Au8Lm2Qv7Wx4Za9Rn5Tf1Gh6Kp0Cd3',
        "secret",
        description="High-entropy AUTH_TOKEN export",
    ),
    Sample(
        'token = "Tk8Lm2Qv7Wx4Za9Rn5Tf1Gh6Kp0Cd3"',
        "secret",
        description="High-entropy token keyword",
    ),
    Sample(
        'credential: "Cr8Lm2Qv7Wx4Za9Rn5Tf1Gh6Kp0Cd3"',
        "secret",
        file_path="credentials.yaml",
        description="High-entropy credential in credentials file",
    ),
    Sample(
        'passwd = "Pw8Lm2Qv7Wx4Za9Rn5Tf1Gh6Kp0Cd3"',
        "secret",
        description="High-entropy passwd keyword",
    ),
    Sample(
        'access_key = "Ak8Lm2Qv7Wx4Za9Rn5Tf1Gh6Kp0Cd3"',
        "secret",
        description="High-entropy access_key keyword",
    ),
    Sample(
        'auth_token = "At8Lm2Qv7Wx4Za9Rn5Tf1Gh6Kp0Cd3"',
        "secret",
        description="High-entropy auth_token keyword",
    ),
    # --- True Negatives: benign values that should NOT be flagged ---
    Sample("550e8400-e29b-41d4-a716-446655440000", "benign", description="UUID v4"),
    Sample("a1b2c3d4e5f6789012345678901234567890abcd", "benign", description="Git commit SHA"),
    Sample("#ff6600", "benign", description="CSS hex color"),
    Sample("v1.2.3-beta+build.123", "benign", description="Semantic version"),
    Sample("+1-555-123-4567", "benign", description="Phone number"),
    Sample("192.168.1.100", "benign", description="IP address"),
    Sample("00:1A:2B:3C:4D:5E", "benign", description="MAC address"),
    Sample("https://api.example.com/v1/users", "benign", description="URL without credentials"),
    Sample("postgres://user:***@localhost/db", "benign", description="Masked URL credentials"),
    Sample("mysql://app:REDACTED@db.local/prod", "benign", description="Redacted URL credentials"),
    Sample('api_key = "your-api-key-here"', "benign", description="Placeholder API key"),
    Sample('api_key = "dummy-key-for-testing"', "benign", description="Dummy key"),
    Sample('api_key = "example_key_replace_me"', "benign", description="Example key"),
    Sample("hello-world-foo-bar-baz-qux", "benign", description="Low-entropy string"),
    Sample("The quick brown fox jumps over the lazy dog", "benign", description="Natural language"),
    Sample("/usr/local/bin/python3", "benign", description="File path"),
    Sample("error: connection refused at 127.0.0.1:5432", "benign", description="Error message"),
    Sample("pk_live_" + "A" * 24, "benign", description="Stripe publishable key (public_exposable → WARN, not BLOCK)"),
    Sample("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "benign", description="IPv6 address"),
    Sample("user@example.com", "benign", description="Email address"),
    Sample("https://docs.example.com/configuration?section=auth", "benign", description="Documentation URL with auth word"),
    Sample("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "benign", description="Base64 image data URL"),
    Sample("eyJnot-a-jwt-here", "benign", description="Broken JWT-like string"),
    Sample("# AWS_KEY = AKIA... (example only)", "benign", description="Commented AWS key example"),
    Sample("API_KEY=", "benign", file_path=".env.example", description="Empty API key placeholder in .env.example"),
    Sample("PASSWORD=", "benign", file_path=".env.example", description="Empty password placeholder in .env.example"),
    Sample('SECRET_KEY = ""', "benign", file_path="settings.example.py", description="Empty SECRET_KEY placeholder"),
    Sample("token = None", "benign", description="None token placeholder"),
    Sample('password = ""', "benign", description="Empty password assignment"),
    Sample("credentials = {}", "benign", description="Empty credentials object"),
    Sample("auth = False", "benign", description="Boolean auth flag"),
    Sample("authorization_config = {}", "benign", description="Authorization config name should not match auth keyword"),
    Sample("author = 'alice'", "benign", description="Author field should not match auth keyword"),
    Sample("authentic = True", "benign", description="Authentic word should not match auth keyword"),
    Sample("const palette = ['#112233', '#445566', '#778899'];", "benign", description="CSS color palette"),
    Sample("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "benign", description="SHA256 digest with prefix"),
    Sample("npm-package-name-1.2.3.tgz", "benign", description="Package artifact name"),
    Sample("arn:aws:iam::123456789012:role/ReadOnlyRole", "benign", description="AWS ARN without secret"),
    Sample("us-east-1", "benign", description="AWS region"),
    Sample("2026-04-23T12:34:56Z", "benign", description="ISO timestamp"),
    Sample("SELECT * FROM users WHERE id = 42", "benign", description="SQL query"),
    Sample("docker.io/library/python:3.13-slim", "benign", description="Docker image tag"),
    Sample("registry.example.com/team/app@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "benign", description="Container digest"),
    Sample("feature/login-rate-limit", "benign", description="Git branch name"),
    Sample("日本語の通常テキストです。秘密情報は含みません。", "benign", description="Japanese natural language"),
    Sample("<div class=\"container\" id=\"main-content\"></div>", "benign", description="HTML snippet"),
    Sample("result = compute_hash(input_data, algorithm='sha256', salt=None)", "benign", description="Function call with hash terminology"),
    Sample("connection_string_template = 'postgres://<user>:<password>@<host>/<db>'", "benign", description="Documentation URL template with placeholders"),
    Sample("postgres://user:<password>@localhost/db", "benign", description="Masked placeholder URL credentials"),
    Sample("mysql://app:changeme@db.local/prod", "benign", description="Changeme URL credentials"),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class BenchmarkResult:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    false_positives: list[Sample] = dataclasses.field(default_factory=list)
    false_negatives: list[Sample] = dataclasses.field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def _is_detected(sample: Sample) -> bool:
    diff_line = DiffLine(
        file_path=sample.file_path,
        line_number=1,
        content=sample.content,
    )
    rule_matches = rules_scan(sample.content)
    entropy_score = entropy_scan(sample.content)
    context_signals = analyze(sample.content, sample.file_path)
    result = aggregate(diff_line, rule_matches, entropy_score, context_signals)
    return result.verdict in (Verdict.BLOCK, Verdict.WARN)


def run() -> BenchmarkResult:
    result = BenchmarkResult()
    for sample in CORPUS:
        detected = _is_detected(sample)
        if sample.label == "secret":
            if detected:
                result.tp += 1
            else:
                result.fn += 1
                result.false_negatives.append(sample)
        else:
            if detected:
                result.fp += 1
                result.false_positives.append(sample)
            else:
                result.tn += 1
    return result


# ---------------------------------------------------------------------------
# pytest
# ---------------------------------------------------------------------------

PRECISION_THRESHOLD = 0.80
RECALL_THRESHOLD = 0.95


def test_benchmark_precision_and_recall() -> None:
    result = run()
    assert len(CORPUS) == 100
    assert result.precision >= PRECISION_THRESHOLD, (
        f"Precision {result.precision:.2%} below threshold {PRECISION_THRESHOLD:.0%}. "
        f"False positives: {[s.description for s in result.false_positives]}"
    )
    assert result.recall >= RECALL_THRESHOLD, (
        f"Recall {result.recall:.2%} below threshold {RECALL_THRESHOLD:.0%}. "
        f"False negatives: {[s.description for s in result.false_negatives]}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    result = run()
    total = len(CORPUS)
    secrets = sum(1 for s in CORPUS if s.label == "secret")
    benign = total - secrets

    print(f"Corpus: {total} samples ({secrets} secrets, {benign} benign)\n")
    print(f"  TP={result.tp}  FP={result.fp}  TN={result.tn}  FN={result.fn}\n")
    print(f"  Precision : {result.precision:.1%}")
    print(f"  Recall    : {result.recall:.1%}")
    print(f"  F1        : {result.f1:.1%}")

    if result.false_positives:
        print("\nFalse Positives:")
        for s in result.false_positives:
            print(f"  - {s.description}")

    if result.false_negatives:
        print("\nFalse Negatives:")
        for s in result.false_negatives:
            print(f"  - {s.description}")
