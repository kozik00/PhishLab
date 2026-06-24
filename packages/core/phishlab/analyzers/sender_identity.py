from __future__ import annotations

import re

from phishlab.analyzers.base import BaseAnalyzer
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity
from phishlab.utils.text_utils import extract_domain

_IMPERSONATION_NAMES = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "linkedin", "github", "dropbox",
    "allegro", "inpost", "mbank", "pko", "dhl", "ups", "fedex",
    "support", "security", "admin", "administrator", "helpdesk",
    "service", "billing", "account", "noreply", "no-reply",
]

_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "icloud.com", "live.com", "yandex.com",
    "wp.pl", "onet.pl", "interia.pl", "o2.pl", "op.pl",
}


class SenderIdentityAnalyzer(BaseAnalyzer):
    def analyze(self, email: NormalizedEmail) -> list[Finding]:
        findings: list[Finding] = []

        display = email.from_display_name.lower()
        from_domain = extract_domain(email.from_address)

        if display and from_domain:
            for brand in _IMPERSONATION_NAMES:
                if brand in display and brand not in from_domain:
                    findings.append(Finding(
                        title="Display name impersonation",
                        category=Category.SENDER_IDENTITY,
                        severity=Severity.HIGH,
                        description=(
                            f"The display name contains '{brand}' but the sending domain "
                            f"'{from_domain}' is not associated with that entity."
                        ),
                        evidence=f"Display name: '{email.from_display_name}', From: {email.from_address}",
                        recommendation="Do not trust the display name alone. Check the actual sender address.",
                        location="From header",
                    ))
                    break

        if display and from_domain in _FREE_EMAIL_DOMAINS:
            if any(brand in display for brand in _IMPERSONATION_NAMES[:12]):
                findings.append(Finding(
                    title="Brand name in display name with free email domain",
                    category=Category.SENDER_IDENTITY,
                    severity=Severity.HIGH,
                    description=(
                        f"The display name references a brand but the email was sent from "
                        f"a free email provider ({from_domain})."
                    ),
                    evidence=f"Display name: '{email.from_display_name}', Domain: {from_domain}",
                    recommendation="Legitimate companies do not send official emails from free email providers.",
                    location="From header",
                ))

        if display and re.search(r"[a-zA-Z]+@[a-zA-Z]+\.\w+", display):
            findings.append(Finding(
                title="Email address in display name",
                category=Category.SENDER_IDENTITY,
                severity=Severity.MEDIUM,
                description=(
                    "The display name contains an email address. This is a common trick "
                    "to make the recipient think the email came from a different address."
                ),
                evidence=f"Display name: '{email.from_display_name}'",
                recommendation="Check the actual From address, not the display name.",
                location="From header",
            ))

        return findings
