from __future__ import annotations

import re
from dataclasses import dataclass, field

from keygate.models import Policy, RuleMatch


@dataclass
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    score: int
    description: str
    policy: Policy = "must_block"
    remediation: list[str] = field(default_factory=list)


_URL_CREDENTIALS_PATTERN = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://"
    r"(?P<user>[^:@/\s]*):"
    r"(?P<pwd>[^@\s]+)@"
)

_MASK_PATTERN = re.compile(
    r"^(?:"
    r"\*+"
    r"|\.{3,}"
    r"|x{3,}"
    r"|redacted"
    r"|placeholder"
    r"|changeme"
    r"|your[_-]?password"
    r"|<[^>]+>"
    r")$",
    re.IGNORECASE,
)


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
    Rule(
        rule_id="stripe-secret-key",
        pattern=re.compile(r"(?:sk|rk)_live_[0-9A-Za-z]{24,}"),
        score=90,
        description="Stripe Live Secret Key detected",
        remediation=[
            "Remove the key from the code",
            "Rotate the Stripe API key in the dashboard",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="stripe-publishable-key",
        pattern=re.compile(r"pk_live_[0-9A-Za-z]{24,}"),
        score=40,
        policy="public_exposable",
        description="Stripe Live Publishable Key detected",
        remediation=[
            "Publishable keys are safe to expose client-side, but avoid hardcoding in server code",
            "Use environment variables if this is unintended",
        ],
    ),
    Rule(
        rule_id="sendgrid-api-key",
        pattern=re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        score=90,
        description="SendGrid API Key detected",
        remediation=[
            "Remove the key from the code",
            "Revoke the key in the SendGrid dashboard",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="url-credentials",
        pattern=_URL_CREDENTIALS_PATTERN,
        score=70,
        description="URL with embedded credentials detected",
        remediation=[
            "Remove the credentials from the URL",
            "Rotate the exposed credentials",
            "Load credentials from environment variables or a secret manager",
        ],
    ),
    Rule(
        rule_id="anthropic-api-key",
        pattern=re.compile(r"sk-ant-[A-Za-z0-9_-]{40,}"),
        score=90,
        description="Anthropic API Key detected",
        remediation=[
            "Remove the key from the code",
            "Rotate the Anthropic API key in the console",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="google-api-key",
        pattern=re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        score=80,
        description="Google API Key detected",
        remediation=[
            "Remove the key from the code",
            "Restrict or rotate the key in Google Cloud Console",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="gitlab-token",
        pattern=re.compile(r"glpat-[0-9A-Za-z_-]{20}"),
        score=85,
        description="GitLab Personal Access Token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the token on GitLab",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="npm-token",
        pattern=re.compile(r"npm_[A-Za-z0-9]{36}"),
        score=85,
        description="npm Access Token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the token on npmjs.com",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="pypi-token",
        pattern=re.compile(r"pypi-[A-Za-z0-9._-]{50,}"),
        score=90,
        description="PyPI API Token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the token on pypi.org",
            "Use environment variables or trusted publishing instead",
        ],
    ),
    Rule(
        rule_id="django-secret-key",
        pattern=re.compile(r"django-insecure-[a-z0-9!@#$%^&*()\-_=+]{50,}"),
        score=85,
        description="Django Secret Key detected",
        remediation=[
            "Remove the secret key from the code",
            "Generate a new secret key and store it in environment variables",
            "Use python-decouple or django-environ to load secrets",
        ],
    ),
    Rule(
        rule_id="twilio-credential",
        pattern=re.compile(r"(?:AC|SK)[a-f0-9]{32}"),
        score=80,
        description="Twilio Account SID or API Key SID detected",
        remediation=[
            "Remove the credential from the code",
            "Rotate the Twilio credentials in the console",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="gcp-service-account",
        pattern=re.compile(r"[\w.-]+@[\w.-]+\.iam\.gserviceaccount\.com"),
        score=85,
        description="GCP Service Account email detected (indicates a service account key file)",
        remediation=[
            "Remove the service account key file from the repository",
            "Revoke and regenerate the service account key in Google Cloud Console",
            "Use Workload Identity Federation or Application Default Credentials instead",
        ],
    ),
    Rule(
        rule_id="azure-connection-string",
        pattern=re.compile(r"AccountKey=[A-Za-z0-9+/]{80,}={0,2}"),
        score=90,
        description="Azure Storage Account Key detected",
        remediation=[
            "Remove the connection string from the code",
            "Rotate the storage account key in Azure Portal",
            "Use managed identities or Azure Key Vault instead",
        ],
    ),
]


def _match_url_credentials(rule: Rule, m: re.Match[str]) -> RuleMatch:
    pwd = m.group("pwd")
    if _MASK_PATTERN.match(pwd):
        return RuleMatch(
            rule_id=rule.rule_id,
            matched_text=m.group(0),
            score=40,
            description="URL with masked credentials (likely documentation)",
            remediation=[
                "If this is a real credential, remove it and rotate",
                "If this is documentation, consider using a placeholder like <password>",
            ],
            policy=rule.policy,
        )
    return RuleMatch(
        rule_id=rule.rule_id,
        matched_text=m.group(0),
        score=rule.score,
        description=rule.description,
        remediation=rule.remediation,
        policy=rule.policy,
    )


def scan_line(content: str) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in RULES:
        for m in rule.pattern.finditer(content):
            if rule.rule_id == "url-credentials":
                matches.append(_match_url_credentials(rule, m))
            else:
                matches.append(RuleMatch(
                    rule_id=rule.rule_id,
                    matched_text=m.group(0),
                    score=rule.score,
                    description=rule.description,
                    remediation=rule.remediation,
                    policy=rule.policy,
                ))
    return matches
