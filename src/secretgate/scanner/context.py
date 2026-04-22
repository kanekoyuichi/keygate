from __future__ import annotations

import re

_DANGEROUS_KEYWORDS = re.compile(
    r"\b(?:api_?key|token|secret|password|passwd|credential|auth)\b",
    re.IGNORECASE,
)
_SENSITIVE_PATH_PARTS = re.compile(
    r"(?:\.env|config|settings|credentials?)",
    re.IGNORECASE,
)
_URL_WITH_AUTH = re.compile(r"https?://[^:@\s]+:[^@\s]+@")


def score_line(content: str, file_path: str) -> int:
    score = 0
    if _DANGEROUS_KEYWORDS.search(content):
        score += 20
    if _SENSITIVE_PATH_PARTS.search(file_path):
        score += 10
    if _URL_WITH_AUTH.search(content):
        score += 20
    return score
