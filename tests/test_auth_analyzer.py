from __future__ import annotations

from phishlab.analyzers.authentication import AuthenticationAnalyzer
from phishlab.models.email import NormalizedEmail


def _make_email(**kwargs) -> NormalizedEmail:
    return NormalizedEmail(**kwargs)


class TestAuthenticationAnalyzer:
    def setup_method(self):
        self.analyzer = AuthenticationAnalyzer()

    def test_detects_missing_auth_results(self):
        email = _make_email(authentication_results="")
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Missing Authentication-Results" in titles

    def test_detects_spf_fail(self):
        email = _make_email(
            authentication_results="mx.example.com; spf=fail smtp.mailfrom=evil.com"
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "SPF check failed" in titles

    def test_detects_spf_softfail(self):
        email = _make_email(
            authentication_results="mx.example.com; spf=softfail smtp.mailfrom=example.com"
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "SPF soft fail" in titles

    def test_detects_spf_none(self):
        email = _make_email(
            authentication_results="mx.example.com; spf=none"
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "No SPF record" in titles

    def test_detects_dkim_fail(self):
        email = _make_email(
            authentication_results="mx.example.com; dkim=fail header.d=example.com"
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "DKIM verification failed" in titles

    def test_detects_dkim_none(self):
        email = _make_email(
            authentication_results="mx.example.com; dkim=none"
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "No DKIM signature" in titles

    def test_detects_dmarc_fail(self):
        email = _make_email(
            authentication_results="mx.example.com; dmarc=fail header.from=example.com"
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "DMARC check failed" in titles

    def test_detects_dmarc_none(self):
        email = _make_email(
            authentication_results="mx.example.com; dmarc=none"
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "No DMARC policy" in titles

    def test_detects_multiple_auth_failures(self):
        email = _make_email(
            authentication_results=(
                "mx.example.com; spf=fail smtp.mailfrom=evil.com; "
                "dkim=none; dmarc=fail header.from=evil.com"
            )
        )
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Multiple authentication failures" in titles

    def test_all_pass_produces_no_findings(self):
        email = _make_email(
            authentication_results=(
                "mx.example.com; spf=pass smtp.mailfrom=example.com; "
                "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
            )
        )
        findings = self.analyzer.analyze(email)
        assert len(findings) == 0

    def test_handles_missing_auth_results_header(self):
        email = _make_email()
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Missing Authentication-Results" in titles
