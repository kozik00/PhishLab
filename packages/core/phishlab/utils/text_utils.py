from __future__ import annotations

import re
from email.utils import parseaddr


def extract_email_address(header_value: str) -> str:
    _, addr = parseaddr(header_value)
    return addr.lower().strip()


def extract_domain(email_or_header: str) -> str:
    addr = extract_email_address(email_or_header)
    if "@" in addr:
        return addr.split("@", 1)[1]
    return ""


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def strip_html_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", "", html)
