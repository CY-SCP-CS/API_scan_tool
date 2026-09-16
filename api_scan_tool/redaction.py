from __future__ import annotations

import re

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|password|secret)\s*([:=])\s*(['\"]?)[^\s,'\"]+", re.MULTILINE),
    re.compile(r"(?i)(mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s'\"]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
]


def redact(text: str) -> str:
    """Remove common credentials before code is sent to an AI service or report."""
    result = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3:
            result = pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]", result)
        else:
            result = pattern.sub("[REDACTED]", result)
    return result
