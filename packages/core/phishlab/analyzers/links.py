from __future__ import annotations

import re
from pathlib import Path

import yaml

from phishlab.analyzers.base import BaseAnalyzer
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity

_RULES_DIR = Path(__file__).resolve().parents[4] / "rules"

_SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "account", "secure", "security", "update", "confirm",
    "password", "credential", "banking", "wallet", "suspend",
]


def _load_shorteners() -> set[str]:
    path = _RULES_DIR / "link_shorteners.yml"
    if not path.exists():
        return set()
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return set(data.get("shorteners", []))


class LinkAnalyzer(BaseAnalyzer):
    def __init__(self) -> None:
        self._shorteners = _load_shorteners()

    def analyze(self, email: NormalizedEmail) -> list[Finding]:
        findings: list[Finding] = []

        for link in email.links:
            if link.display_domain and link.target_domain:
                if (
                    link.display_domain != link.target_domain
                    and link.display_domain != link.visible_text
                    and "." in link.display_domain
                ):
                    findings.append(Finding(
                        title="Link text domain differs from actual URL",
                        category=Category.LINKS,
                        severity=Severity.CRITICAL,
                        description=(
                            "The visible link text shows one domain but the actual URL points "
                            "to a different domain. This is a classic phishing technique."
                        ),
                        evidence=(
                            f"Visible: {link.display_domain}, "
                            f"Actual: {link.target_domain}"
                        ),
                        recommendation="Do not click this link. The destination is not what it appears.",
                        location=f"Link: {link.href[:100]}",
                    ))

            if link.is_ip_based:
                findings.append(Finding(
                    title="IP-based URL",
                    category=Category.LINKS,
                    severity=Severity.HIGH,
                    description=(
                        "The URL uses an IP address instead of a domain name. "
                        "Legitimate services rarely use IP addresses in links."
                    ),
                    evidence=f"URL: {link.href[:100]}",
                    recommendation="Do not click IP-based links in emails.",
                    location=f"Link: {link.href[:100]}",
                ))

            if link.is_shortened or link.domain.lower() in self._shorteners:
                findings.append(Finding(
                    title="Shortened URL",
                    category=Category.LINKS,
                    severity=Severity.MEDIUM,
                    description=(
                        "The URL uses a URL shortener service, hiding the actual destination."
                    ),
                    evidence=f"Shortener domain: {link.domain}",
                    recommendation="Be cautious with shortened links. The destination is hidden.",
                    location=f"Link: {link.href[:100]}",
                ))

            if link.href.startswith("http://"):
                findings.append(Finding(
                    title="Link uses HTTP instead of HTTPS",
                    category=Category.LINKS,
                    severity=Severity.LOW,
                    description="The URL uses unencrypted HTTP instead of HTTPS.",
                    evidence=f"URL: {link.href[:100]}",
                    recommendation="Legitimate services use HTTPS. HTTP links may be insecure.",
                    location=f"Link: {link.href[:100]}",
                ))

            if link.is_punycode:
                findings.append(Finding(
                    title="Punycode domain",
                    category=Category.LINKS,
                    severity=Severity.HIGH,
                    description=(
                        "The URL uses a punycode-encoded domain, which can visually impersonate "
                        "a legitimate domain using look-alike characters."
                    ),
                    evidence=f"Domain: {link.domain}",
                    recommendation="Punycode domains are often used for visual impersonation attacks.",
                    location=f"Link: {link.href[:100]}",
                ))

            subdomain_count = link.domain.count(".")
            if subdomain_count >= 3:
                findings.append(Finding(
                    title="Excessive subdomains",
                    category=Category.LINKS,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The domain has {subdomain_count} levels of subdomains. "
                        "Attackers use deep subdomains to hide the real domain."
                    ),
                    evidence=f"Domain: {link.domain}",
                    recommendation="Check the actual registered domain (the last two parts).",
                    location=f"Link: {link.href[:100]}",
                    confidence=0.7,
                ))

            path_lower = (link.path + link.query).lower()
            for keyword in _SUSPICIOUS_URL_KEYWORDS:
                if keyword in path_lower:
                    findings.append(Finding(
                        title=f"Suspicious keyword in URL: '{keyword}'",
                        category=Category.LINKS,
                        severity=Severity.LOW,
                        description=f"The URL path contains the keyword '{keyword}'.",
                        evidence=f"URL: {link.href[:100]}",
                        recommendation="Verify the URL before entering any information.",
                        location=f"Link: {link.href[:100]}",
                        confidence=0.5,
                        tags=["url-keyword"],
                    ))
                    break

        return findings
