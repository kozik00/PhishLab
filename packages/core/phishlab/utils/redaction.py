from __future__ import annotations

import re

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("API key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+", re.IGNORECASE)),
    ("Bearer token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)),
    ("Authorization header", re.compile(r"(?i)authorization\s*:\s*\S+.*", re.IGNORECASE)),
    ("Password field", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE)),
    ("Private key block", re.compile(r"-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----", re.IGNORECASE)),
    ("Session/cookie", re.compile(r"(?i)(session[_-]?id|cookie)\s*[:=]\s*\S+", re.IGNORECASE)),
    ("Database URL with creds", re.compile(r"(?i)(postgres|mysql|mongodb)://\S+:\S+@", re.IGNORECASE)),
    ("AWS key", re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE)),
]


def redact_secrets(text: str) -> str:
    result = text
    for label, pattern in _SECRET_PATTERNS:
        result = pattern.sub(f"[REDACTED {label}]", result)
    return result


def redact_email_address(email: str) -> str:
    if "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"
