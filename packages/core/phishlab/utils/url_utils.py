from __future__ import annotations

import re
from urllib.parse import urlparse, unquote

_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
    r"|^\[?[0-9a-fA-F:]+\]?$"
)

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "bl.ink", "short.io", "cutt.ly",
    "rb.gy", "lnkd.in", "youtu.be",
}


def parse_url(url: str) -> dict[str, str]:
    decoded = unquote(url)
    parsed = urlparse(decoded)
    return {
        "scheme": parsed.scheme,
        "domain": parsed.hostname or "",
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }


def is_ip_based(domain: str) -> bool:
    return bool(_IP_PATTERN.match(domain))


def is_shortened(domain: str) -> bool:
    return domain.lower() in _SHORTENER_DOMAINS


def is_punycode(domain: str) -> bool:
    return domain.startswith("xn--") or any(
        part.startswith("xn--") for part in domain.split(".")
    )


def uses_https(url: str) -> bool:
    return urlparse(url).scheme == "https"


def extract_display_domain(text: str) -> str:
    """Extract a domain from visible link text if it looks like a URL."""
    match = re.search(r"https?://([^/\s]+)", text)
    if match:
        return match.group(1).lower()
    match = re.search(r"(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})", text)
    if match:
        return match.group(0).lower()
    return ""
