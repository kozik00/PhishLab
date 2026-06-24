from __future__ import annotations

from phishlab.analyzers.links import LinkAnalyzer
from phishlab.models.email import EmailLink, NormalizedEmail


def _make_email(links: list[EmailLink] | None = None) -> NormalizedEmail:
    return NormalizedEmail(links=links or [])


def _make_link(**kwargs) -> EmailLink:
    defaults = {
        "visible_text": "",
        "href": "https://example.com",
        "scheme": "https",
        "domain": "example.com",
        "path": "/",
        "query": "",
        "is_ip_based": False,
        "is_shortened": False,
        "is_punycode": False,
        "uses_https": True,
        "display_domain": "",
        "target_domain": "example.com",
    }
    defaults.update(kwargs)
    return EmailLink(**defaults)


class TestLinkAnalyzer:
    def setup_method(self):
        self.analyzer = LinkAnalyzer()

    def test_detects_display_href_domain_mismatch(self):
        link = _make_link(
            visible_text="https://login.microsoft.com/verify",
            display_domain="login.microsoft.com",
            target_domain="192.168.1.100",
            href="http://192.168.1.100/verify",
        )
        email = _make_email(links=[link])
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Link text domain differs from actual URL" in titles

    def test_detects_ip_based_url(self):
        link = _make_link(
            href="http://192.168.1.100/phish",
            domain="192.168.1.100",
            is_ip_based=True,
        )
        email = _make_email(links=[link])
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "IP-based URL" in titles

    def test_detects_shortened_url(self):
        link = _make_link(
            href="https://bit.ly/abc123",
            domain="bit.ly",
            is_shortened=True,
        )
        email = _make_email(links=[link])
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Shortened URL" in titles

    def test_detects_http_link(self):
        link = _make_link(
            href="http://example.com/page",
            scheme="http",
            uses_https=False,
        )
        email = _make_email(links=[link])
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Link uses HTTP instead of HTTPS" in titles

    def test_detects_punycode_domain(self):
        link = _make_link(
            href="https://xn--pple-43d.com/login",
            domain="xn--pple-43d.com",
            is_punycode=True,
        )
        email = _make_email(links=[link])
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Punycode domain" in titles

    def test_detects_excessive_subdomains(self):
        link = _make_link(
            href="https://login.secure.verify.evil.com/page",
            domain="login.secure.verify.evil.com",
        )
        email = _make_email(links=[link])
        findings = self.analyzer.analyze(email)
        titles = [f.title for f in findings]
        assert "Excessive subdomains" in titles

    def test_detects_suspicious_keyword_in_url(self):
        link = _make_link(
            href="https://example.com/login/verify",
            path="/login/verify",
        )
        email = _make_email(links=[link])
        findings = self.analyzer.analyze(email)
        has_keyword_finding = any("Suspicious keyword" in f.title for f in findings)
        assert has_keyword_finding

    def test_clean_link_has_no_findings(self):
        link = _make_link(
            href="https://example.com/about",
            domain="example.com",
            path="/about",
        )
        email = _make_email(links=[link])
        findings = self.analyzer.analyze(email)
        assert len(findings) == 0

    def test_no_findings_for_empty_links(self):
        email = _make_email(links=[])
        findings = self.analyzer.analyze(email)
        assert len(findings) == 0
