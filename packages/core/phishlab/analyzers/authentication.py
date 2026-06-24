from __future__ import annotations

import re

from phishlab.analyzers.base import BaseAnalyzer
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity


def _find_result(auth_results: str, mechanism: str) -> str | None:
    pattern = rf"{mechanism}\s*=\s*(\w+)"
    match = re.search(pattern, auth_results, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


class AuthenticationAnalyzer(BaseAnalyzer):
    def analyze(self, email: NormalizedEmail) -> list[Finding]:
        findings: list[Finding] = []
        auth = email.authentication_results

        if not auth:
            findings.append(Finding(
                title="Missing Authentication-Results",
                category=Category.AUTHENTICATION,
                severity=Severity.MEDIUM,
                description=(
                    "No Authentication-Results header was found. This header is added by "
                    "receiving mail servers and reports SPF, DKIM, and DMARC results."
                ),
                evidence="Authentication-Results header is absent",
                recommendation=(
                    "The absence of this header means authentication checks could not be evaluated. "
                    "Exercise caution."
                ),
                location="Authentication-Results header",
                confidence=0.7,
            ))
            return findings

        spf = _find_result(auth, "spf")
        dkim = _find_result(auth, "dkim")
        dmarc = _find_result(auth, "dmarc")

        if spf == "fail":
            findings.append(Finding(
                title="SPF check failed",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                description=(
                    "The sending server is not authorized to send email for this domain. "
                    "SPF (Sender Policy Framework) verification failed."
                ),
                evidence=f"spf={spf}",
                recommendation="This email may be spoofed. Do not trust the sender address.",
                location="Authentication-Results header",
            ))
        elif spf == "softfail":
            findings.append(Finding(
                title="SPF soft fail",
                category=Category.AUTHENTICATION,
                severity=Severity.MEDIUM,
                description=(
                    "The sending server is not explicitly authorized to send email for this domain. "
                    "SPF returned a soft fail, which means the domain owner has not strictly forbidden it."
                ),
                evidence=f"spf={spf}",
                recommendation="Treat with caution. The sender may not be fully authorized.",
                location="Authentication-Results header",
            ))
        elif spf == "none":
            findings.append(Finding(
                title="No SPF record",
                category=Category.AUTHENTICATION,
                severity=Severity.LOW,
                description="The sending domain does not publish an SPF record.",
                evidence=f"spf={spf}",
                recommendation="Domains without SPF records cannot be verified via SPF.",
                location="Authentication-Results header",
                confidence=0.6,
            ))

        if dkim == "fail":
            findings.append(Finding(
                title="DKIM verification failed",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                description=(
                    "The DKIM signature is invalid. This means the email content may have been "
                    "modified in transit, or the signature was forged."
                ),
                evidence=f"dkim={dkim}",
                recommendation="Do not trust this email. The content may have been tampered with.",
                location="Authentication-Results header",
            ))
        elif dkim == "none":
            findings.append(Finding(
                title="No DKIM signature",
                category=Category.AUTHENTICATION,
                severity=Severity.LOW,
                description="The email does not contain a DKIM signature.",
                evidence=f"dkim={dkim}",
                recommendation="Without DKIM, email integrity cannot be verified.",
                location="Authentication-Results header",
                confidence=0.5,
            ))

        if dmarc == "fail":
            findings.append(Finding(
                title="DMARC check failed",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                description=(
                    "DMARC verification failed. The email does not align with the domain's "
                    "published authentication policy."
                ),
                evidence=f"dmarc={dmarc}",
                recommendation="This email likely does not come from the claimed sender domain.",
                location="Authentication-Results header",
            ))
        elif dmarc == "none":
            findings.append(Finding(
                title="No DMARC policy",
                category=Category.AUTHENTICATION,
                severity=Severity.LOW,
                description="The sending domain does not publish a DMARC policy.",
                evidence=f"dmarc={dmarc}",
                recommendation="Without DMARC, domain-level authentication policy cannot be enforced.",
                location="Authentication-Results header",
                confidence=0.5,
            ))

        if spf == "fail" and dmarc == "fail":
            findings.append(Finding(
                title="Multiple authentication failures",
                category=Category.AUTHENTICATION,
                severity=Severity.CRITICAL,
                description=(
                    "Both SPF and DMARC checks failed. This is a strong indicator that "
                    "the sender address is spoofed."
                ),
                evidence=f"spf={spf}, dmarc={dmarc}",
                recommendation="Do not trust this email. The sender is almost certainly not who they claim.",
                location="Authentication-Results header",
            ))

        return findings
