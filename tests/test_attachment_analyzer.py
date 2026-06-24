from __future__ import annotations

from phishlab.analyzers.attachments import AttachmentAnalyzer
from phishlab.models.email import EmailAttachment, NormalizedEmail


def _make_email(attachments: list[EmailAttachment] | None = None) -> NormalizedEmail:
    return NormalizedEmail(attachments=attachments or [])


def _make_attachment(**kwargs) -> EmailAttachment:
    defaults = {
        "filename": "document.pdf",
        "content_type": "application/pdf",
        "size_bytes": 1024,
        "sha256": "a" * 64,
        "extension": ".pdf",
        "detected_extensions": [],
        "has_double_extension": False,
        "is_suspicious_type": False,
    }
    defaults.update(kwargs)
    return EmailAttachment(**defaults)


class TestAttachmentAnalyzer:
    def setup_method(self):
        self.analyzer = AttachmentAnalyzer()

    def test_detects_double_extension(self):
        att = _make_attachment(
            filename="invoice.pdf.exe",
            extension=".exe",
            detected_extensions=[".pdf", ".exe"],
            has_double_extension=True,
            is_suspicious_type=True,
        )
        email = _make_email(attachments=[att])
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Double file extension detected" in titles

    def test_detects_executable_extension(self):
        att = _make_attachment(
            filename="setup.exe",
            extension=".exe",
            is_suspicious_type=True,
        )
        email = _make_email(attachments=[att])
        findings = self.analyzer.analyze(email)
        has_suspicious = any("Suspicious file type" in f.title for f in findings)
        assert has_suspicious

    def test_detects_macro_capable_office_file(self):
        att = _make_attachment(
            filename="report.docm",
            content_type="application/vnd.ms-word.document.macroEnabled.12",
            extension=".docm",
            is_suspicious_type=True,
        )
        email = _make_email(attachments=[att])
        findings = self.analyzer.analyze(email)
        has_suspicious = any("Suspicious file type" in f.title for f in findings)
        assert has_suspicious

    def test_detects_script_extension(self):
        att = _make_attachment(
            filename="update.js",
            content_type="application/javascript",
            extension=".js",
            is_suspicious_type=True,
        )
        email = _make_email(attachments=[att])
        findings = self.analyzer.analyze(email)
        has_suspicious = any("Suspicious file type" in f.title for f in findings)
        assert has_suspicious

    def test_safe_pdf_has_no_suspicious_findings(self):
        att = _make_attachment(
            filename="report.pdf",
            content_type="application/pdf",
            extension=".pdf",
        )
        email = _make_email(attachments=[att])
        findings = self.analyzer.analyze(email)
        suspicious = [f for f in findings if "Suspicious" in f.title or "Double" in f.title]
        assert len(suspicious) == 0

    def test_detects_mime_mismatch(self):
        att = _make_attachment(
            filename="image.png",
            content_type="application/pdf",
            extension=".png",
        )
        email = _make_email(attachments=[att])
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "MIME type mismatch" in titles

    def test_no_findings_for_no_attachments(self):
        email = _make_email(attachments=[])
        findings = self.analyzer.analyze(email)
        assert len(findings) == 0

    def test_does_not_execute_anything(self):
        att = _make_attachment(
            filename="malware.exe",
            extension=".exe",
            is_suspicious_type=True,
        )
        email = _make_email(attachments=[att])
        findings = self.analyzer.analyze(email)
        assert isinstance(findings, list)
