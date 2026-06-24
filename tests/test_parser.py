from __future__ import annotations

from pathlib import Path

import pytest

from phishlab.models.email import NormalizedEmail
from phishlab.parser.eml_parser import parse_eml, parse_eml_file


class TestSimpleEmail:
    def test_parses_from_address(self, simple_email: NormalizedEmail):
        assert simple_email.from_address == "john.doe@example.com"

    def test_parses_from_display_name(self, simple_email: NormalizedEmail):
        assert simple_email.from_display_name == "John Doe"

    def test_parses_to(self, simple_email: NormalizedEmail):
        assert simple_email.to == ["jane.smith@example.com"]

    def test_parses_subject(self, simple_email: NormalizedEmail):
        assert simple_email.subject == "Meeting Tomorrow"

    def test_parses_message_id(self, simple_email: NormalizedEmail):
        assert simple_email.message_id == "<abc123@mail.example.com>"

    def test_parses_date(self, simple_email: NormalizedEmail):
        assert simple_email.date is not None
        assert simple_email.date.year == 2024
        assert simple_email.date.month == 1
        assert simple_email.date.day == 15

    def test_parses_text_body(self, simple_email: NormalizedEmail):
        assert "meeting tomorrow" in simple_email.text_body.lower()

    def test_has_no_html_body(self, simple_email: NormalizedEmail):
        assert simple_email.html_body == ""

    def test_has_no_attachments(self, simple_email: NormalizedEmail):
        assert simple_email.attachments == []

    def test_has_no_links(self, simple_email: NormalizedEmail):
        assert simple_email.links == []


class TestMultipartEmail:
    def test_parses_text_body(self, multipart_email: NormalizedEmail):
        assert "weekly update" in multipart_email.text_body.lower()

    def test_parses_html_body(self, multipart_email: NormalizedEmail):
        assert "<h1>" in multipart_email.html_body

    def test_extracts_links_from_html(self, multipart_email: NormalizedEmail):
        assert len(multipart_email.links) >= 1
        hrefs = [link.href for link in multipart_email.links]
        assert "https://company-example.com/blog" in hrefs

    def test_link_uses_https(self, multipart_email: NormalizedEmail):
        blog_link = next(
            l for l in multipart_email.links
            if "company-example.com" in l.href
        )
        assert blog_link.uses_https is True

    def test_parses_reply_to(self, multipart_email: NormalizedEmail):
        assert multipart_email.reply_to == "noreply@company-example.com"

    def test_parses_return_path(self, multipart_email: NormalizedEmail):
        assert multipart_email.return_path == "bounce@company-example.com"


class TestMalformedEmail:
    def test_does_not_crash(self, malformed_email: NormalizedEmail):
        assert malformed_email is not None

    def test_has_text_body(self, malformed_email: NormalizedEmail):
        assert "malformed" in malformed_email.text_body.lower()

    def test_date_is_none(self, malformed_email: NormalizedEmail):
        assert malformed_email.date is None

    def test_missing_message_id(self, malformed_email: NormalizedEmail):
        assert malformed_email.message_id == ""

    def test_to_is_empty(self, malformed_email: NormalizedEmail):
        assert malformed_email.to == []


class TestEmailWithAttachments:
    def test_extracts_attachments(self, email_with_attachments: NormalizedEmail):
        assert len(email_with_attachments.attachments) == 2

    def test_first_attachment_is_pdf(self, email_with_attachments: NormalizedEmail):
        pdf = email_with_attachments.attachments[0]
        assert pdf.filename == "report.pdf"
        assert pdf.extension == ".pdf"
        assert pdf.has_double_extension is False
        assert pdf.is_suspicious_type is False

    def test_second_attachment_has_double_extension(self, email_with_attachments: NormalizedEmail):
        exe = email_with_attachments.attachments[1]
        assert exe.filename == "invoice.pdf.exe"
        assert exe.has_double_extension is True
        assert exe.is_suspicious_type is True

    def test_sha256_is_computed(self, email_with_attachments: NormalizedEmail):
        for att in email_with_attachments.attachments:
            assert len(att.sha256) == 64
            assert all(c in "0123456789abcdef" for c in att.sha256)

    def test_size_bytes_is_positive(self, email_with_attachments: NormalizedEmail):
        for att in email_with_attachments.attachments:
            assert att.size_bytes > 0


class TestPhishingLinksEmail:
    def test_extracts_links(self, phishing_links_email: NormalizedEmail):
        assert len(phishing_links_email.links) >= 2

    def test_detects_ip_based_link(self, phishing_links_email: NormalizedEmail):
        ip_links = [l for l in phishing_links_email.links if l.is_ip_based]
        assert len(ip_links) >= 1

    def test_detects_shortened_link(self, phishing_links_email: NormalizedEmail):
        short_links = [l for l in phishing_links_email.links if l.is_shortened]
        assert len(short_links) >= 1

    def test_display_domain_mismatch(self, phishing_links_email: NormalizedEmail):
        ip_link = next(l for l in phishing_links_email.links if l.is_ip_based)
        assert ip_link.display_domain != ip_link.target_domain

    def test_parses_authentication_results(self, phishing_links_email: NormalizedEmail):
        assert "spf=fail" in phishing_links_email.authentication_results

    def test_return_path_differs_from_from(self, phishing_links_email: NormalizedEmail):
        from_domain = phishing_links_email.from_address.split("@")[1]
        rp_domain = phishing_links_email.return_path.split("@")[1]
        assert from_domain != rp_domain


class TestMissingHeadersEmail:
    def test_does_not_crash(self, missing_headers_email: NormalizedEmail):
        assert missing_headers_email is not None

    def test_from_is_empty(self, missing_headers_email: NormalizedEmail):
        assert missing_headers_email.from_address == ""

    def test_subject_is_empty(self, missing_headers_email: NormalizedEmail):
        assert missing_headers_email.subject == ""

    def test_message_id_is_empty(self, missing_headers_email: NormalizedEmail):
        assert missing_headers_email.message_id == ""

    def test_has_text_body(self, missing_headers_email: NormalizedEmail):
        assert "missing most standard headers" in missing_headers_email.text_body.lower()


class TestParseEmlFromBytes:
    def test_accepts_bytes(self, fixtures_dir: Path):
        raw = (fixtures_dir / "simple.eml").read_bytes()
        result = parse_eml(raw)
        assert result.from_address == "john.doe@example.com"

    def test_raw_headers_populated(self, simple_email: NormalizedEmail):
        assert "From" in simple_email.raw_headers
        assert len(simple_email.raw_headers["From"]) >= 1
