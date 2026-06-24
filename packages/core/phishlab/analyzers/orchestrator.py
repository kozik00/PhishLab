from __future__ import annotations

from phishlab.analyzers.attachments import AttachmentAnalyzer
from phishlab.analyzers.authentication import AuthenticationAnalyzer
from phishlab.analyzers.base import BaseAnalyzer
from phishlab.analyzers.content import ContentAnalyzer
from phishlab.analyzers.domains import DomainAnalyzer
from phishlab.analyzers.headers import HeaderAnalyzer
from phishlab.analyzers.links import LinkAnalyzer
from phishlab.analyzers.sender_identity import SenderIdentityAnalyzer
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Finding


def get_default_analyzers() -> list[BaseAnalyzer]:
    return [
        HeaderAnalyzer(),
        SenderIdentityAnalyzer(),
        AuthenticationAnalyzer(),
        LinkAnalyzer(),
        DomainAnalyzer(),
        AttachmentAnalyzer(),
        ContentAnalyzer(),
    ]


def run_analysis(
    email: NormalizedEmail,
    analyzers: list[BaseAnalyzer] | None = None,
) -> list[Finding]:
    if analyzers is None:
        analyzers = get_default_analyzers()

    findings: list[Finding] = []
    for analyzer in analyzers:
        findings.extend(analyzer.analyze(email))

    return findings
