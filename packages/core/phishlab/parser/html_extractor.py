from __future__ import annotations

from bs4 import BeautifulSoup

from phishlab.models.email import EmailLink
from phishlab.utils.url_utils import (
    extract_display_domain,
    is_ip_based,
    is_punycode,
    is_shortened,
    parse_url,
    uses_https,
)


def extract_links_from_html(html: str) -> list[EmailLink]:
    soup = BeautifulSoup(html, "html.parser")
    links: list[EmailLink] = []

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href or href.startswith("mailto:") or href.startswith("#"):
            continue

        visible_text = anchor.get_text(strip=True)
        parts = parse_url(href)
        domain = parts["domain"]

        links.append(
            EmailLink(
                visible_text=visible_text,
                href=href,
                scheme=parts["scheme"],
                domain=domain,
                path=parts["path"],
                query=parts["query"],
                is_ip_based=is_ip_based(domain),
                is_shortened=is_shortened(domain),
                is_punycode=is_punycode(domain),
                uses_https=uses_https(href),
                display_domain=extract_display_domain(visible_text),
                target_domain=domain,
            )
        )

    return links


def extract_text_from_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "head"]):
        tag.decompose()
    return soup.get_text(separator="\n", strip=True)
