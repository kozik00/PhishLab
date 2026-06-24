from __future__ import annotations

import re

from phishlab.analyzers.base import BaseAnalyzer
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity
from phishlab.utils.text_utils import extract_domain


class HeaderAnalyzer(BaseAnalyzer):
    def analyze(self, email: NormalizedEmail) -> list[Finding]:
        findings: list[Finding] = []

        from_domain = extract_domain(email.from_address)

        if email.reply_to and from_domain:
            reply_domain = extract_domain(email.reply_to)
            if reply_domain and reply_domain != from_domain:
                findings.append(Finding(
                    title="Reply-To domain mismatch",
                    category=Category.SENDER_IDENTITY,
                    severity=Severity.MEDIUM,
                    description=(
                        "The Reply-To address uses a different domain than the From address. "
                        "Replies will go to a different domain than the apparent sender."
                    ),
                    evidence=f"From domain: {from_domain}, Reply-To domain: {reply_domain}",
                    recommendation="Verify the sender's identity before replying.",
                    location="Reply-To header",
                ))

        if email.return_path and from_domain:
            rp_domain = extract_domain(email.return_path)
            if rp_domain and rp_domain != from_domain:
                findings.append(Finding(
                    title="Return-Path domain mismatch",
                    category=Category.SENDER_IDENTITY,
                    severity=Severity.HIGH,
                    description=(
                        "The Return-Path uses a different domain than the From address. "
                        "This often indicates the email was sent through a different mail system "
                        "than the claimed sender domain."
                    ),
                    evidence=f"From domain: {from_domain}, Return-Path domain: {rp_domain}",
                    recommendation="Treat this email with suspicion. The sender may not be who they claim.",
                    location="Return-Path header",
                ))

        if not email.message_id:
            findings.append(Finding(
                title="Missing Message-ID",
                category=Category.SENDER_IDENTITY,
                severity=Severity.LOW,
                description="The email is missing a Message-ID header, which is unusual for legitimate mail servers.",
                evidence="Message-ID header is absent",
                recommendation="Missing Message-ID can indicate the email was crafted manually.",
                location="Message-ID header",
            ))
        elif email.message_id and from_domain:
            mid_match = re.search(r"@([^>]+)>?$", email.message_id)
            if mid_match:
                mid_domain = mid_match.group(1).lower()
                if mid_domain != from_domain and not mid_domain.endswith(f".{from_domain}"):
                    findings.append(Finding(
                        title="Message-ID domain mismatch",
                        category=Category.SENDER_IDENTITY,
                        severity=Severity.LOW,
                        description=(
                            "The Message-ID domain does not match the From domain. "
                            "This can indicate the email was sent from a different system."
                        ),
                        evidence=f"From domain: {from_domain}, Message-ID domain: {mid_domain}",
                        recommendation="This is a weak indicator on its own but may reinforce other findings.",
                        location="Message-ID header",
                        confidence=0.5,
                    ))

        if not email.date:
            findings.append(Finding(
                title="Missing or invalid Date header",
                category=Category.SENDER_IDENTITY,
                severity=Severity.LOW,
                description="The email has a missing or unparseable Date header.",
                evidence=f"Raw Date value: '{email.date_raw}'",
                recommendation="Legitimate email servers always include a valid Date header.",
                location="Date header",
            ))

        return findings
