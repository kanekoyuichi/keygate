from __future__ import annotations

import re
import base64
import binascii
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

_BASIC_AUTH_PATTERN = re.compile(
    r"\bAuthorization\s*:\s*Basic\s+(?P<value>[A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/=])",
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
        pattern=re.compile(r"sk-(?!ant-)[A-Za-z0-9_-]{32,}"),
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
    Rule(
        rule_id="azure-sas-token",
        pattern=re.compile(
            r"(?:\?|&)"
            r"(?:"
            r"sv=\d{4}-\d{2}-\d{2}[^\"'\s]*\bsig=[A-Za-z0-9%+/=]{20,}"
            r"|sig=[A-Za-z0-9%+/=]{20,}[^\"'\s]*\bsv=\d{4}-\d{2}-\d{2}"
            r")",
            re.IGNORECASE,
        ),
        score=85,
        description="Azure SAS token detected",
        remediation=[
            "Remove the SAS token from the code",
            "Revoke or regenerate the shared access signature",
            "Use managed identities or short-lived credentials instead",
        ],
    ),
    Rule(
        rule_id="huggingface-token",
        pattern=re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
        score=85,
        description="Hugging Face token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the token in Hugging Face settings",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="dockerhub-token",
        pattern=re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"),
        score=85,
        description="Docker Hub access token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the token in Docker Hub",
            "Use environment variables or credential helpers instead",
        ],
    ),
    Rule(
        rule_id="vercel-token",
        pattern=re.compile(
            r"\bvercel[_-]?token\s*[:=]\s*[\"']?[A-Za-z0-9]{24,}\b",
            re.IGNORECASE,
        ),
        score=80,
        description="Vercel token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the token in Vercel account settings",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="sentry-dsn",
        pattern=re.compile(
            r"https://[A-Fa-f0-9]{32}@[A-Za-z0-9.-]+/[0-9]+"
        ),
        score=40,
        policy="public_exposable",
        description="Sentry DSN detected",
        remediation=[
            "Review whether this DSN should be public",
            "Use environment variables if this is server-side configuration",
        ],
    ),
    Rule(
        rule_id="datadog-api-key",
        pattern=re.compile(
            r"\b(?:datadog|dd)[_-]?(?:api|app)[_-]?key\s*[:=]\s*[\"']?[A-Fa-f0-9]{32,40}\b",
            re.IGNORECASE,
        ),
        score=85,
        description="Datadog API or application key detected",
        remediation=[
            "Remove the key from the code",
            "Revoke or rotate the key in Datadog",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="discord-token",
        pattern=re.compile(
            r"\b(?:mfa\.[A-Za-z0-9_-]{20,}|[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b"
        ),
        score=85,
        description="Discord token detected",
        remediation=[
            "Remove the token from the code",
            "Reset the Discord bot token",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="discord-webhook-url",
        pattern=re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}"
        ),
        score=90,
        description="Discord webhook URL detected",
        remediation=[
            "Remove the webhook URL from the code",
            "Delete or rotate the Discord webhook",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="telegram-bot-token",
        pattern=re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b"),
        score=85,
        description="Telegram bot token detected",
        remediation=[
            "Remove the token from the code",
            "Revoke the bot token with BotFather",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="twilio-auth-token",
        pattern=re.compile(
            r"\btwilio[_-]?auth[_-]?token\s*[:=]\s*[\"']?[A-Fa-f0-9]{32}\b",
            re.IGNORECASE,
        ),
        score=85,
        description="Twilio auth token detected",
        remediation=[
            "Remove the token from the code",
            "Rotate the Twilio auth token",
            "Use environment variables instead",
        ],
    ),
    Rule(
        rule_id="authorization-bearer",
        pattern=re.compile(
            r"\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{20,}\b",
            re.IGNORECASE,
        ),
        score=70,
        description="Authorization Bearer token detected",
        remediation=[
            "Remove the bearer token from the code",
            "Revoke or rotate the exposed credential",
            "Load authorization headers from environment variables instead",
        ],
    ),
    Rule(
        rule_id="authorization-basic",
        pattern=_BASIC_AUTH_PATTERN,
        score=70,
        description="Authorization Basic credentials detected",
        remediation=[
            "Remove the Basic authorization header from the code",
            "Rotate the exposed password or token",
            "Load credentials from environment variables instead",
        ],
    ),
    # --- PII rules ---
    # PII alone is capped to WARN. If non-PII signals (entropy, context, path)
    # are strong enough to reach block_score without the PII rule, the result
    # escalates to BLOCK. See scoring.aggregate for the cap logic.
    Rule(
        rule_id="pii-email",
        pattern=re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        score=50,
        policy="pii",
        description="Email address detected",
        remediation=[
            "Remove or anonymize the email address",
            "Use placeholder values in non-production code",
        ],
    ),
    Rule(
        rule_id="pii-phone-jp",
        pattern=re.compile(
            r"(?:"
            r"\b(?:0[5-9]0|0[1-9]\d{0,3})[-\s]\d{1,4}[-\s]\d{4}"
            r"|\+81[-\s]?\d{1,4}[-\s]\d{1,4}[-\s]\d{4}"
            r"|\b0[5789]0\d{8}"
            r"|(?<!\d)\(0\d{1,4}\)[-\s]?\d{1,4}[-\s]\d{4}"
            r"|\b0\d{1,4}\(\d{1,4}\)\d{4}"
            r")(?:(?:\s*(?:ext\.?|x|内線)\s*\d{1,6})\b|\b)"
        ),
        score=50,
        policy="pii",
        description="Japanese phone number detected",
        remediation=[
            "Remove or anonymize the phone number",
            "Use placeholder values in non-production code",
        ],
    ),
    Rule(
        rule_id="pii-credit-card",
        pattern=re.compile(
            r"\b(?:"
            r"4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{1,4}"
            r"|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}"
            r"|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}"
            r"|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}"
            r"|3(?:0[0-5]|[68][0-9])[0-9][-\s]?[0-9]{6}[-\s]?[0-9]{4}"
            r"|35(?:2[89]|[3-8][0-9])[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}"
            r")\b"
        ),
        score=50,
        policy="pii",
        description="Credit card number detected",
        remediation=[
            "Remove the credit card number immediately",
            "Rotate or cancel the card if it was a real number",
            "Never store raw card numbers — use a payment tokenization service",
        ],
    ),
    Rule(
        rule_id="pii-ssn",
        pattern=re.compile(
            r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
        ),
        score=50,
        policy="pii",
        description="US Social Security Number detected",
        remediation=[
            "Remove the SSN from the code",
            "Use anonymized or tokenized identifiers instead",
        ],
    ),
    Rule(
        rule_id="pii-iban",
        pattern=re.compile(
            r"\b(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DK|DO"
            r"|EE|EG|ES|FI|FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IQ|IS|IT"
            r"|JO|KW|KZ|LB|LC|LI|LT|LU|LV|MC|MD|ME|MK|MR|MT|MU|NL|NO|PK"
            r"|PL|PS|PT|QA|RO|RS|SA|SC|SE|SI|SK|SM|ST|SV|TL|TN|TR|UA|VA|VG|XK)"
            r"\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}\b",
            re.IGNORECASE,
        ),
        score=50,
        policy="pii",
        description="IBAN (International Bank Account Number) detected",
        remediation=[
            "Remove the IBAN from the code",
            "Use anonymized identifiers in non-production code",
        ],
    ),
    Rule(
        rule_id="pii-uk-nin",
        pattern=re.compile(
            r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[A-D]\b"
        ),
        score=50,
        policy="pii",
        description="UK National Insurance Number detected",
        remediation=[
            "Remove the NI Number from the code",
            "Use anonymized identifiers in non-production code",
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


def _match_basic_auth(rule: Rule, m: re.Match[str]) -> RuleMatch | None:
    value = m.group("value")
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None

    if ":" not in decoded:
        return None
    user, password = decoded.split(":", 1)
    if not user or not password or _MASK_PATTERN.match(password):
        return None

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
            elif rule.rule_id == "authorization-basic":
                basic_match = _match_basic_auth(rule, m)
                if basic_match is not None:
                    matches.append(basic_match)
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
