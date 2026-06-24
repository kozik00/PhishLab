from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class EmailLink(BaseModel):
    visible_text: str = ""
    href: str = ""
    scheme: str = ""
    domain: str = ""
    path: str = ""
    query: str = ""
    is_ip_based: bool = False
    is_shortened: bool = False
    is_punycode: bool = False
    uses_https: bool = False
    display_domain: str = ""
    target_domain: str = ""


class EmailAttachment(BaseModel):
    filename: str = ""
    content_type: str = ""
    size_bytes: int = 0
    sha256: str = ""
    extension: str = ""
    detected_extensions: list[str] = Field(default_factory=list)
    has_double_extension: bool = False
    is_suspicious_type: bool = False


class ReceivedHop(BaseModel):
    from_host: str = ""
    by_host: str = ""
    timestamp: str = ""
    raw: str = ""


class NormalizedEmail(BaseModel):
    message_id: str = ""
    subject: str = ""
    from_address: str = ""
    from_display_name: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    date: datetime | None = None
    date_raw: str = ""
    received_hops: list[ReceivedHop] = Field(default_factory=list)
    authentication_results: str = ""
    text_body: str = ""
    html_body: str = ""
    links: list[EmailLink] = Field(default_factory=list)
    attachments: list[EmailAttachment] = Field(default_factory=list)
    raw_headers: dict[str, list[str]] = Field(default_factory=dict)
