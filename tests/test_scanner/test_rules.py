import pytest
from secretgate.scanner.rules import scan_line


@pytest.mark.parametrize("content,rule_id", [
    ("AWS_KEY=AKIAIOSFODNN7EXAMPLE1234", "aws-access-key"),
    ("key = sk-abcdefghijklmnopqrstuvwxyz123456", "openai-api-key"),
    ("token = ghp_" + "A" * 36, "github-token"),
    ("token = xoxb-EXAMPLEFAKETOKEN1234", "slack-token"),
    ("-----BEGIN RSA PRIVATE KEY-----", "private-key-pem"),
    ("token = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "jwt"),
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
