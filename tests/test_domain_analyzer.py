from __future__ import annotations

from phishlab.analyzers.domains import DomainAnalyzer
from phishlab.models.email import EmailLink, NormalizedEmail


def _make_email(**kwargs) -> NormalizedEmail:
    return NormalizedEmail(**kwargs)


class TestDomainAnalyzer:
    def setup_method(self):
        self.analyzer = DomainAnalyzer()

    def test_detects_typosquatting_microsoft(self):
        email = _make_email(from_address="alert@micros0ft.com")
        findings = self.analyzer.analyze(email)
        typo_findings = [f for f in findings if "typosquatting" in f.title.lower() or "substitution" in f.title.lower()]
        assert len(typo_findings) >= 1

    def test_detects_typosquatting_paypal(self):
        email = _make_email(from_address="alert@paypa1.com")
        findings = self.analyzer.analyze(email)
        typo_findings = [f for f in findings if "typosquatting" in f.title.lower() or "substitution" in f.title.lower()]
        assert len(typo_findings) >= 1

    def test_detects_typosquatting_google(self):
        email = _make_email(from_address="alert@go0gle.com")
        findings = self.analyzer.analyze(email)
        typo_findings = [f for f in findings if "typosquatting" in f.title.lower() or "substitution" in f.title.lower()]
        assert len(typo_findings) >= 1

    def test_no_false_positive_for_legit_domain(self):
        email = _make_email(from_address="user@microsoft.com")
        findings = self.analyzer.analyze(email)
        typo_findings = [f for f in findings if "typosquatting" in f.title.lower() or "substitution" in f.title.lower()]
        assert len(typo_findings) == 0

    def test_no_false_positive_for_unrelated_domain(self):
        email = _make_email(from_address="user@randomcompany.com")
        findings = self.analyzer.analyze(email)
        typo_findings = [f for f in findings if "typosquatting" in f.title.lower() or "substitution" in f.title.lower()]
        assert len(typo_findings) == 0

    def test_detects_brand_keyword_in_domain(self):
        email = _make_email(from_address="user@microsoft-login-verify.com")
        findings = self.analyzer.analyze(email)
        brand_findings = [f for f in findings if "brand" in f.title.lower() or "keyword" in f.title.lower()]
        assert len(brand_findings) >= 1

    def test_checks_link_domains(self):
        link = EmailLink(
            href="https://micros0ft.com/login",
            domain="micros0ft.com",
            target_domain="micros0ft.com",
        )
        email = _make_email(
            from_address="user@example.com",
            links=[link],
        )
        findings = self.analyzer.analyze(email)
        typo_findings = [f for f in findings if "typosquatting" in f.title.lower() or "substitution" in f.title.lower()]
        assert len(typo_findings) >= 1

    def test_skips_legitimate_alias_domains(self):
        email = _make_email(from_address="user@outlook.com")
        findings = self.analyzer.analyze(email)
        typo_findings = [f for f in findings if "typosquatting" in f.title.lower()]
        assert len(typo_findings) == 0

    def test_detects_polish_brand_typosquatting(self):
        email = _make_email(from_address="info@a1legro.pl")
        findings = self.analyzer.analyze(email)
        typo_findings = [f for f in findings if "typosquatting" in f.title.lower() or "substitution" in f.title.lower()]
        assert len(typo_findings) >= 1
