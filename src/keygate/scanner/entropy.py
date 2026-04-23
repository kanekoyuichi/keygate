from __future__ import annotations

import math
import re

_SPLITTER = re.compile(r"""[\s'"=:,\[\]{}()]""")


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
    for token in tokens:
        if len(token) >= min_length and calculate_shannon_entropy(token) >= threshold:
            return 20
    return 0
