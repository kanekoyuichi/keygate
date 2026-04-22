from __future__ import annotations

import re
from dataclasses import dataclass, field

from secretgate.models import RuleMatch


@dataclass
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    score: int
    description: str
    remediation: list[str] = field(default_factory=list)


RULES: list[Rule] = [
    Rule(
        rule_id="aws-access-key",
        pattern=re.compile(r"(?:AKIA|ASIA|AROA)[0-9A-Z]{16}"),
        score=90,
        description="AWS Access Key detected",
        remediation=[
            "Remove the key from the code",
            "Rotate the AWS credentials immediately",
            "Use environment variables or AWS IAM roles instead",
        ],
    ),
    Rule(
        rule_id="openai-api-key",
        pattern=re.compile(r"sk-[A-Za-z0-9]{32,}"),
        score=85,
        description="OpenAI API Key detected",
        remediation=[
            "Remove the key from the code",
            "Rotate the OpenAI API key",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="github-token",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
        score=85,
        description="GitHub Personal Access Token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the token on GitHub",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="slack-token",
        pattern=re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        score=80,
        description="Slack Token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the token on Slack",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="private-key-pem",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        score=100,
        description="Private Key (PEM) detected",
        remediation=[
            "Remove the private key from the code",
            "Generate a new key pair",
            "Store private keys outside the repository",
        ],
    ),
    Rule(
        rule_id="jwt",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        score=60,
        description="JSON Web Token (JWT) detected",
        remediation=[
            "Remove the JWT from the code",
            "Invalidate the token if it is a real credential",
            "Use environment variables instead",
        ],
    ),
]


def scan_line(content: str) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in RULES:
        m = rule.pattern.search(content)
        if m:
            matches.append(RuleMatch(
                rule_id=rule.rule_id,
                matched_text=m.group(0),
                score=rule.score,
                description=rule.description,
                remediation=rule.remediation,
            ))
    return matches
