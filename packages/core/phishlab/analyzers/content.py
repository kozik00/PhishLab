from __future__ import annotations

from pathlib import Path

import yaml

from phishlab.analyzers.base import BaseAnalyzer
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity

_RULES_DIR = Path(__file__).resolve().parents[4] / "rules"


def _load_content_patterns() -> dict[str, dict]:
    path = _RULES_DIR / "content_patterns.yml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


_CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "urgency": "The email creates a sense of urgency to pressure the recipient into acting quickly.",
    "account_suspension": "The email threatens account suspension or lockout.",
    "credential_request": "The email asks the recipient to provide or verify credentials.",
    "payment_request": "The email requests a payment or references an invoice.",
    "gift_card": "The email requests gift card purchases, a common scam technique.",
    "attachment_request": "The email urges the recipient to open an attachment or enable macros.",
    "link_click_request": "The email pressures the recipient to click a link.",
    "impersonation_language": "The email impersonates an internal department or authority figure.",
}

_CATEGORY_RECOMMENDATIONS: dict[str, str] = {
    "urgency": "Legitimate organizations rarely require immediate action via email. Take your time.",
    "account_suspension": "Contact the service provider directly through their official website, not through this email.",
    "credential_request": "Never provide passwords or credentials in response to an email.",
    "payment_request": "Verify payment requests through a separate communication channel.",
    "gift_card": "Gift card requests via email are almost always scams, even if they appear to come from your boss.",
    "attachment_request": "Do not open attachments or enable macros unless you are certain of the sender.",
    "link_click_request": "Hover over links to verify the destination before clicking.",
    "impersonation_language": "Verify the request by contacting the department directly through known channels.",
}


class ContentAnalyzer(BaseAnalyzer):
    def __init__(self) -> None:
        self._patterns = _load_content_patterns()

    def analyze(self, email: NormalizedEmail) -> list[Finding]:
        findings: list[Finding] = []
        text = self._get_searchable_text(email)
        text_lower = text.lower()

        matched_categories: set[str] = set()

        for category_key, config in self._patterns.items():
            severity = Severity(config.get("severity", "medium"))
            patterns = config.get("patterns", [])

            matched_patterns: list[str] = []
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    matched_patterns.append(pattern)

            if matched_patterns:
                matched_categories.add(category_key)
                description = _CATEGORY_DESCRIPTIONS.get(category_key, "Suspicious content detected.")
                recommendation = _CATEGORY_RECOMMENDATIONS.get(category_key, "Exercise caution.")

                findings.append(Finding(
                    title=f"Phishing signal: {category_key.replace('_', ' ')}",
                    category=Category.CONTENT,
                    severity=severity,
                    description=description,
                    evidence=f"Matched patterns: {', '.join(matched_patterns[:5])}",
                    recommendation=recommendation,
                    location="Email body/subject",
                    tags=[category_key],
                ))

        if len(matched_categories) >= 3:
            findings.append(Finding(
                title="Multiple phishing signals detected",
                category=Category.CONTENT,
                severity=Severity.HIGH,
                description=(
                    f"The email contains {len(matched_categories)} different categories of "
                    f"phishing signals: {', '.join(sorted(matched_categories))}. "
                    "The combination of multiple signals is a strong phishing indicator."
                ),
                evidence=f"Categories: {', '.join(sorted(matched_categories))}",
                recommendation="This email has a high likelihood of being a phishing attempt.",
                location="Email body/subject",
                tags=["multi-signal"],
            ))

        return findings

    def _get_searchable_text(self, email: NormalizedEmail) -> str:
        parts: list[str] = []
        if email.subject:
            parts.append(email.subject)
        if email.text_body:
            parts.append(email.text_body)
        if email.html_body and not email.text_body:
            from phishlab.parser.html_extractor import extract_text_from_html
            parts.append(extract_text_from_html(email.html_body))
        return "\n".join(parts)
