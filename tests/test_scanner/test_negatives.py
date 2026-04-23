"""Negative tests: ensure common false-positive sources do not BLOCK.

Spec §10.4 lists negatives we want suppressed. Cases that depend on
allowlist or inline-ignore configuration (.env.example by path,
README samples, fixture paths) are policy concerns and out of scope here.

Strong rule matches in placeholder/sample contexts are intentionally
handled at the scanner layer now, so examples in README/docs and
fixture-like paths can regress here without relying on repo config.
"""
from __future__ import annotations

from keygate.models import DiffLine, Verdict
from keygate.scanner import context, entropy, rules, scoring


def _scan(content: str, file_path: str = "src/app.py") -> tuple[Verdict, int]:
    line = DiffLine(file_path=file_path, line_number=1, content=content)
    rule_matches = rules.scan_line(content)
    e = entropy.scan_line(content, threshold=4.2)
    ctx = context.score_line(content, file_path)
    result = scoring.aggregate(line, rule_matches, e, ctx)
    return result.verdict, result.total_score


def test_url_credentials_redacted_does_not_block():
    verdict, _ = _scan("DB_URL=postgres://admin:redacted@db.example.com/app")
    assert verdict != Verdict.BLOCK


def test_url_credentials_changeme_placeholder_does_not_block():
    verdict, _ = _scan("DATABASE_URL=mysql://root:changeme@localhost/dev")
    assert verdict != Verdict.BLOCK


def test_plain_base64_text_does_not_block():
    """A generic base64-ish blob in docs without keywords should not BLOCK."""
    verdict, _ = _scan(
        "comment: SGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBzZWNyZXQ=",
        file_path="docs/example.md",
    )
    assert verdict != Verdict.BLOCK


def test_low_entropy_assignment_in_docs_does_not_block():
    """Trivial password assignment in docs (no rule, low entropy) should not BLOCK."""
    verdict, _ = _scan('password = "test"', file_path="docs/guide.md")
    assert verdict != Verdict.BLOCK


def test_readme_openai_example_does_not_block():
    verdict, score = _scan(
        'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"  # example only',
        file_path="README.md",
    )
    assert verdict != Verdict.BLOCK
    assert score == 40


def test_fixture_aws_example_does_not_block():
    verdict, score = _scan(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE1234"  # dummy sample',
        file_path="tests/fixtures/sample.env",
    )
    assert verdict != Verdict.BLOCK
    assert score == 40
