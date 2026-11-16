from __future__ import annotations

import math
import re

_SPLITTER = re.compile(r"""[\s'"=:,\[\]{}()]""")

# Hex tops out at log2(16) = 4.0 bits/char, below the default threshold, so
# hex-only secrets (Cloudflare, Datadog, Twilio, ...) could never score.
# Random hex of 32+ chars stays above 3.3 in ~99% of cases.
_HEX_TOKEN = re.compile(r"[0-9a-f]{32,}|[0-9A-F]{32,}")
_HEX_THRESHOLD_OFFSET = 0.9
# Digests, commit SHAs and IDs are hex too; keep the strict threshold for them.
_HASH_CONTEXT = re.compile(
    r"(?:^|[^A-Za-z])"
    r"(?:sha\d*|md5|digest|checksum|hash|integrity|commit|ref|rev|revision|etag|fingerprint"
    r"|uuid|guid|id)"
    r"(?:[^A-Za-z]|$)",
    re.IGNORECASE,
)


def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def scan_line(content: str, threshold: float = 4.2, min_length: int = 20) -> int:
    tokens = _SPLITTER.split(content)
    hash_context: bool | None = None
    for token in tokens:
        if len(token) < min_length:
            continue
        limit = threshold
        if _HEX_TOKEN.fullmatch(token):
            if hash_context is None:
                hash_context = bool(_HASH_CONTEXT.search(content))
            if not hash_context:
                limit = threshold - _HEX_THRESHOLD_OFFSET
        if calculate_shannon_entropy(token) >= limit:
            return 20
    return 0
