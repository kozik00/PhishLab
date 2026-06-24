from __future__ import annotations

from phishlab.analyzers.orchestrator import get_default_analyzers, run_analysis
from phishlab.models.email import NormalizedEmail


class TestOrchestrator:
    def test_returns_list_of_findings(self):
        email = NormalizedEmail(
            from_address="alert@micros0ft-alert.com",
            from_display_name="Microsoft Security",
            return_path="bounce@shady.net",
            authentication_results="mx.example.com; spf=fail; dkim=none; dmarc=fail",
            text_body="Your account will be suspended. Verify your identity immediately.",
        )
        findings = run_analysis(email)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_has_seven_default_analyzers(self):
        analyzers = get_default_analyzers()
        assert len(analyzers) == 7

    def test_all_findings_have_required_fields(self):
        email = NormalizedEmail(
            from_address="phisher@evil.com",
            text_body="Click here to verify your account immediately.",
        )
        findings = run_analysis(email)
        for f in findings:
            assert f.title
            assert f.category
            assert f.severity
            assert f.id

    def test_clean_email_produces_few_findings(self):
        from datetime import datetime, timezone
        email = NormalizedEmail(
            from_address="john@company.com",
            from_display_name="John Smith",
            reply_to="john@company.com",
            return_path="john@company.com",
            message_id="<abc@company.com>",
            date=datetime.now(timezone.utc),
            authentication_results="mx.company.com; spf=pass; dkim=pass; dmarc=pass",
            subject="Team Lunch Friday",
            text_body="Hi everyone, lunch at noon on Friday. See you there!",
        )
        findings = run_analysis(email)
        assert len(findings) <= 2

    def test_phishing_email_produces_many_findings(self, phishing_links_email):
        findings = run_analysis(phishing_links_email)
        assert len(findings) >= 5
