from __future__ import annotations

import email
import email.policy
import re
from datetime import datetime
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

from phishlab.models.email import EmailLink, NormalizedEmail, ReceivedHop
from phishlab.parser.attachment_extractor import extract_attachments
from phishlab.parser.html_extractor import extract_links_from_html, extract_text_from_html
from phishlab.utils.url_utils import (
    extract_display_domain,
    is_ip_based,
    is_punycode,
    is_shortened,
    parse_url,
    uses_https,
)


def parse_eml_file(path: str | Path) -> NormalizedEmail:
    path = Path(path)
    raw = path.read_bytes()
    return parse_eml(raw)


def parse_eml(raw: bytes) -> NormalizedEmail:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    return _message_to_model(msg)


def _message_to_model(msg: Message) -> NormalizedEmail:
    from_header = msg.get("From", "")
    from_display, from_addr = parseaddr(from_header)

    reply_to = _extract_addr(msg.get("Reply-To", ""))
    return_path = _extract_addr(msg.get("Return-Path", ""))

    to_addrs = _parse_address_list(msg.get("To", ""))
    cc_addrs = _parse_address_list(msg.get("Cc", ""))

    date_raw = msg.get("Date", "")
    date = _parse_date(date_raw)

    received_hops = _parse_received_headers(msg.get_all("Received") or [])
    auth_results = msg.get("Authentication-Results", "")

    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain" and not text_body:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    text_body = _safe_decode(payload, charset)
            elif ct == "text/html" and not html_body:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html_body = _safe_decode(payload, charset)
    else:
        ct = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            decoded = _safe_decode(payload, charset)
            if ct == "text/html":
                html_body = decoded
            else:
                text_body = decoded

    links = _extract_all_links(text_body, html_body)
    attachments = extract_attachments(msg)

    raw_headers: dict[str, list[str]] = {}
    for key in msg.keys():
        raw_headers.setdefault(key, []).append(str(msg[key]))

    return NormalizedEmail(
        message_id=msg.get("Message-ID", ""),
        subject=msg.get("Subject", ""),
        from_address=from_addr.lower(),
        from_display_name=from_display,
        reply_to=reply_to,
        return_path=return_path,
        to=to_addrs,
        cc=cc_addrs,
        date=date,
        date_raw=date_raw,
        received_hops=received_hops,
        authentication_results=auth_results,
        text_body=text_body,
        html_body=html_body,
        links=links,
        attachments=attachments,
        raw_headers=raw_headers,
    )


def _extract_addr(header_value: str) -> str:
    if not header_value:
        return ""
    _, addr = parseaddr(header_value)
    return addr.lower().strip()


def _parse_address_list(header_value: str) -> list[str]:
    if not header_value:
        return []
    addrs: list[str] = []
    for part in header_value.split(","):
        _, addr = parseaddr(part.strip())
        if addr:
            addrs.append(addr.lower().strip())
    return addrs


def _parse_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        return None


def _parse_received_headers(received_list: list[str]) -> list[ReceivedHop]:
    hops: list[ReceivedHop] = []
    for raw in received_list:
        from_match = re.search(r"from\s+(\S+)", raw, re.IGNORECASE)
        by_match = re.search(r"by\s+(\S+)", raw, re.IGNORECASE)
        hops.append(
            ReceivedHop(
                from_host=from_match.group(1) if from_match else "",
                by_host=by_match.group(1) if by_match else "",
                raw=raw.strip(),
            )
        )
    return hops


_TEXT_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")


def _extract_links_from_text(text: str) -> list[EmailLink]:
    links: list[EmailLink] = []
    for match in _TEXT_URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,;:!?)")
        parts = parse_url(url)
        domain = parts["domain"]
        links.append(
            EmailLink(
                visible_text=url,
                href=url,
                scheme=parts["scheme"],
                domain=domain,
                path=parts["path"],
                query=parts["query"],
                is_ip_based=is_ip_based(domain),
                is_shortened=is_shortened(domain),
                is_punycode=is_punycode(domain),
                uses_https=uses_https(url),
                display_domain=domain,
                target_domain=domain,
            )
        )
    return links


def _extract_all_links(text_body: str, html_body: str) -> list[EmailLink]:
    links: list[EmailLink] = []
    seen_hrefs: set[str] = set()

    if html_body:
        for link in extract_links_from_html(html_body):
            if link.href not in seen_hrefs:
                seen_hrefs.add(link.href)
                links.append(link)

    if text_body:
        for link in _extract_links_from_text(text_body):
            if link.href not in seen_hrefs:
                seen_hrefs.add(link.href)
                links.append(link)

    return links


def _safe_decode(payload: bytes, charset: str) -> str:
    try:
        return payload.decode(charset)
    except (UnicodeDecodeError, LookupError):
        return payload.decode("utf-8", errors="replace")
