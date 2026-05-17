from __future__ import annotations

import re
from dataclasses import dataclass

_HIGH_KEYWORDS = re.compile(
    r"(?:^|[^A-Za-z])"
    r"(?:"
    r"api[_-]?key"
    r"|access[_-]?key"
    r"|access[_-]?token"
    r"|private[_-]?key"
    r"|auth[_-]?token"
    r"|session[_-]?secret"
    r"|client[_-]?secret"
    r"|jwt[_-]?secret"
    r"|database[_-]?password"
    r"|db[_-]?password"
    r"|secret"
    r"|password"
    r"|passwd"
    r")"
    r"(?:[^A-Za-z]|$)",
    re.IGNORECASE,
)
_MID_KEYWORDS = re.compile(
    r"(?:^|[^A-Za-z])(?:token|credential|auth)(?:[^A-Za-z]|$)",
    re.IGNORECASE,
)

_VERY_SENSITIVE_PATH = re.compile(r"(?:^|/)\.env(?:\.|$)", re.IGNORECASE)
_SECRET_TOOL_PATH = re.compile(
    r"(?:"
    r"(?:^|/)\.npmrc$"
    r"|(?:^|/)\.pypirc$"
    r"|(?:^|/)kubeconfig$"
    r"|(?:^|/)terraform\.tfvars$"
    r"|(?:^|/)\.docker/config\.json$"
    r"|(?:^|/)docker/config\.json$"
    r")",
    re.IGNORECASE,
)
_SENSITIVE_PATH = re.compile(r"(?:settings|credentials?|secrets?|config)", re.IGNORECASE)
_CONFIG_EXT = re.compile(r"\.(?:ya?ml|toml|ini|properties)$", re.IGNORECASE)

_ASSIGN_COLON_EQ = re.compile(r"""^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*[:=]\s*["']?""")
_ASSIGN_EXPORT = re.compile(r"""^\s*export\s+[A-Za-z_][A-Za-z0-9_]*\s*=""")


@dataclass(frozen=True)
class ContextSignals:
    keyword_score: int = 0
    keyword_tier: str = ""
    path_score: int = 0
    assignment_score: int = 0

    @property
    def total(self) -> int:
        return self.keyword_score + self.path_score + self.assignment_score


def _keyword(content: str) -> tuple[int, str]:
    if _HIGH_KEYWORDS.search(content):
        return 25, "high"
    if _MID_KEYWORDS.search(content):
        return 15, "mid"
    return 0, ""


def _path(file_path: str) -> int:
    if _VERY_SENSITIVE_PATH.search(file_path) or _SECRET_TOOL_PATH.search(file_path):
        return 20
    if _SENSITIVE_PATH.search(file_path):
        return 15
    if _CONFIG_EXT.search(file_path):
        return 10
    return 0


def _assignment(content: str) -> int:
    if _ASSIGN_EXPORT.match(content) or _ASSIGN_COLON_EQ.match(content):
        return 15
    return 0


def score_line(content: str, file_path: str) -> ContextSignals:
    keyword_score, keyword_tier = _keyword(content)
    return ContextSignals(
        keyword_score=keyword_score,
        keyword_tier=keyword_tier,
        path_score=_path(file_path),
        assignment_score=_assignment(content),
    )
