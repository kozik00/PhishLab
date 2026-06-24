from __future__ import annotations

from phishlab.analyzers.headers import HeaderAnalyzer
from phishlab.models.email import NormalizedEmail


def _make_email(**kwargs) -> NormalizedEmail:
    return NormalizedEmail(**kwargs)


class TestHeaderAnalyzer:
    def setup_method(self):
        self.analyzer = HeaderAnalyzer()

    def test_detects_reply_to_mismatch(self):
        email = _make_email(
            from_address="user@company.com",
            reply_to="user@evil.com",
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Reply-To domain mismatch" in titles

    def test_no_finding_when_reply_to_matches(self):
        email = _make_email(
            from_address="user@company.com",
            reply_to="other@company.com",
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Reply-To domain mismatch" not in titles

    def test_detects_return_path_mismatch(self):
        email = _make_email(
            from_address="user@company.com",
            return_path="bounce@shady.net",
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Return-Path domain mismatch" in titles

    def test_no_finding_when_return_path_matches(self):
        email = _make_email(
            from_address="user@company.com",
            return_path="bounce@company.com",
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Return-Path domain mismatch" not in titles

    def test_detects_missing_message_id(self):
        email = _make_email(from_address="user@company.com", message_id="")
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Missing Message-ID" in titles

    def test_detects_message_id_domain_mismatch(self):
        email = _make_email(
            from_address="user@company.com",
            message_id="<abc123@other-server.net>",
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Message-ID domain mismatch" in titles

    def test_no_finding_when_message_id_matches(self):
        email = _make_email(
            from_address="user@company.com",
            message_id="<abc123@company.com>",
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Message-ID domain mismatch" not in titles

    def test_detects_missing_date(self):
        email = _make_email(from_address="user@company.com")
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Missing or invalid Date header" in titles

    def test_clean_email_has_minimal_findings(self):
        from datetime import datetime, timezone
        email = _make_email(
            from_address="user@company.com",
            reply_to="user@company.com",
            return_path="user@company.com",
            message_id="<abc@company.com>",
            date=datetime.now(timezone.utc),
        )
        findings = self.analyzer.analyze(email)
        assert len(findings) == 0
