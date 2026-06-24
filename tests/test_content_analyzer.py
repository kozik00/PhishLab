from __future__ import annotations

from phishlab.analyzers.content import ContentAnalyzer
from phishlab.models.email import NormalizedEmail


def _make_email(**kwargs) -> NormalizedEmail:
    return NormalizedEmail(**kwargs)


class TestContentAnalyzer:
    def setup_method(self):
        self.analyzer = ContentAnalyzer()

    def test_detects_urgency(self):
        email = _make_email(
            subject="Urgent: Act Now",
            text_body="You must act immediately or your account will be closed.",
        )
        findings = self.analyzer.analyze(email)
        categories = [f.tags[0] if f.tags else "" for f in findings]
        assert "urgency" in categories

    def test_detects_account_suspension(self):
        email = _make_email(
            text_body="Your account will be suspended unless you verify your identity.",
        )
        findings = self.analyzer.analyze(email)
        categories = [f.tags[0] if f.tags else "" for f in findings]
        assert "account_suspension" in categories

    def test_detects_credential_request(self):
        email = _make_email(
            text_body="Please verify your account by entering your password.",
        )
        findings = self.analyzer.analyze(email)
        categories = [f.tags[0] if f.tags else "" for f in findings]
        assert "credential_request" in categories

    def test_detects_payment_request(self):
        email = _make_email(
            text_body="Payment is due. Please see attached invoice.",
        )
        findings = self.analyzer.analyze(email)
        categories = [f.tags[0] if f.tags else "" for f in findings]
        assert "payment_request" in categories

    def test_detects_gift_card_scam(self):
        email = _make_email(
            text_body="I need you to buy gift cards urgently. Send me the codes.",
        )
        findings = self.analyzer.analyze(email)
        categories = [f.tags[0] if f.tags else "" for f in findings]
        assert "gift_card" in categories

    def test_detects_attachment_request(self):
        email = _make_email(
            text_body="Please open the attached document and enable macros to view.",
        )
        findings = self.analyzer.analyze(email)
        categories = [f.tags[0] if f.tags else "" for f in findings]
        assert "attachment_request" in categories

    def test_detects_multiple_signals(self):
        email = _make_email(
            subject="Urgent Security Alert",
            text_body=(
                "Your account has been compromised. You must verify your identity "
                "immediately. Click here to confirm your password. Your account will "
                "be suspended within 24 hours."
            ),
        )
        findings = self.analyzer.analyze(email)
        has_multi = any("multi-signal" in (f.tags or []) for f in findings)
        assert has_multi

    def test_detects_polish_urgency(self):
        email = _make_email(
            text_body="Pilne! Twoje konto zostanie zablokowane. Potwierdź swoje dane natychmiast.",
        )
        findings = self.analyzer.analyze(email)
        categories = [f.tags[0] if f.tags else "" for f in findings]
        assert "urgency" in categories

    def test_detects_polish_account_suspension(self):
        email = _make_email(
            text_body="Twoje konto zostanie zablokowane jeśli nie zweryfikujesz swoich danych.",
        )
        findings = self.analyzer.analyze(email)
        categories = [f.tags[0] if f.tags else "" for f in findings]
        assert "account_suspension" in categories

    def test_clean_email_has_no_findings(self):
        email = _make_email(
            subject="Meeting Tomorrow",
            text_body="Hi, just a reminder about our meeting tomorrow at 10am. Best, John.",
        )
        findings = self.analyzer.analyze(email)
        assert len(findings) == 0

    def test_uses_html_body_when_no_text(self):
        email = _make_email(
            html_body="<html><body><p>Your account will be suspended. Act immediately.</p></body></html>",
        )
        findings = self.analyzer.analyze(email)
        assert len(findings) > 0
