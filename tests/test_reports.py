from __future__ import annotations

import json

from phishlab.models.analysis import AnalysisResult, CategoryScore, RiskLevel
from phishlab.models.email import EmailAttachment, EmailLink, NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity
from phishlab.reports.generator import (
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    generate_user_report,
)
from phishlab.scoring.risk_score import build_analysis_result


def _sample_email() -> NormalizedEmail:
    return NormalizedEmail(
        message_id="<test-123@example.com>",
        subject="Urgent: Verify Your Account",
        from_address="security@micros0ft-alert.com",
        from_display_name="Microsoft Security",
        reply_to="security@micros0ft-alert.com",
        return_path="bounce@shady.net",
        to=["victim@example.com"],
        date_raw="Thu, 18 Jan 2024 09:00:00 +0000",
        authentication_results="mx.example.com; spf=fail; dkim=none; dmarc=fail",
        text_body="Your account has been compromised. Verify immediately.",
        links=[
            EmailLink(
                visible_text="https://login.microsoft.com",
                href="http://192.168.1.100/verify",
                domain="192.168.1.100",
                is_ip_based=True,
                uses_https=False,
                display_domain="login.microsoft.com",
                target_domain="192.168.1.100",
            ),
        ],
        attachments=[
            EmailAttachment(
                filename="invoice.pdf.exe",
                content_type="application/octet-stream",
                size_bytes=4096,
                sha256="a" * 64,
                extension=".exe",
                detected_extensions=[".pdf", ".exe"],
                has_double_extension=True,
                is_suspicious_type=True,
            ),
        ],
    )


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            title="Return-Path domain mismatch",
            category=Category.SENDER_IDENTITY,
            severity=Severity.HIGH,
            evidence="From: micros0ft-alert.com, Return-Path: shady.net",
            recommendation="Treat with suspicion.",
        ),
        Finding(
            title="SPF check failed",
            category=Category.AUTHENTICATION,
            severity=Severity.HIGH,
            evidence="spf=fail",
            recommendation="Sender may be spoofed.",
        ),
        Finding(
            title="Link text domain differs from actual URL",
            category=Category.LINKS,
            severity=Severity.CRITICAL,
            evidence="Visible: login.microsoft.com, Actual: 192.168.1.100",
            recommendation="Do not click.",
        ),
        Finding(
            title="Double file extension detected",
            category=Category.ATTACHMENTS,
            severity=Severity.CRITICAL,
            evidence="invoice.pdf.exe",
            recommendation="Do not open.",
        ),
        Finding(
            title="Phishing signal: urgency",
            category=Category.CONTENT,
            severity=Severity.MEDIUM,
            evidence="Matched: immediately",
            recommendation="Take your time.",
        ),
    ]


def _sample_result() -> tuple[AnalysisResult, NormalizedEmail]:
    email = _sample_email()
    findings = _sample_findings()
    result = build_analysis_result(email, findings)
    return result, email


class TestJsonReport:
    def test_valid_json(self):
        result, email = _sample_result()
        report = generate_json_report(result, email)
        data = json.loads(report)
        assert isinstance(data, dict)

    def test_contains_risk_score(self):
        result, email = _sample_result()
        report = generate_json_report(result, email)
        data = json.loads(report)
        assert "risk_score" in data
        assert data["risk_score"] == result.risk_score

    def test_contains_risk_level(self):
        result, email = _sample_result()
        report = generate_json_report(result, email)
        data = json.loads(report)
        assert "risk_level" in data

    def test_contains_findings(self):
        result, email = _sample_result()
        report = generate_json_report(result, email)
        data = json.loads(report)
        assert "findings" in data
        assert len(data["findings"]) == 5

    def test_contains_email_summary(self):
        result, email = _sample_result()
        report = generate_json_report(result, email)
        data = json.loads(report)
        assert "email_summary" in data
        assert data["email_summary"]["subject"] == "Urgent: Verify Your Account"

    def test_contains_indicators(self):
        result, email = _sample_result()
        report = generate_json_report(result, email)
        data = json.loads(report)
        assert "indicators" in data
        assert len(data["indicators"]["links"]) == 1
        assert len(data["indicators"]["attachments"]) == 1

    def test_does_not_contain_raw_body(self):
        result, email = _sample_result()
        report = generate_json_report(result, email)
        assert "Your account has been compromised" not in report


class TestMarkdownReport:
    def test_contains_risk_score(self):
        result, email = _sample_result()
        report = generate_markdown_report(result, email)
        assert "100" in report or str(int(result.risk_score)) in report

    def test_contains_subject(self):
        result, email = _sample_result()
        report = generate_markdown_report(result, email)
        assert "Urgent: Verify Your Account" in report

    def test_contains_findings(self):
        result, email = _sample_result()
        report = generate_markdown_report(result, email)
        assert "Return-Path domain mismatch" in report
        assert "SPF check failed" in report

    def test_contains_links_table(self):
        result, email = _sample_result()
        report = generate_markdown_report(result, email)
        assert "192.168.1.100" in report

    def test_contains_attachments_table(self):
        result, email = _sample_result()
        report = generate_markdown_report(result, email)
        assert "invoice.pdf.exe" in report

    def test_contains_phishlab_footer(self):
        result, email = _sample_result()
        report = generate_markdown_report(result, email)
        assert "PhishLab" in report


class TestHtmlReport:
    def test_is_valid_html(self):
        result, email = _sample_result()
        report = generate_html_report(result, email)
        assert report.strip().startswith("<!DOCTYPE html>")
        assert "</html>" in report

    def test_contains_risk_score(self):
        result, email = _sample_result()
        report = generate_html_report(result, email)
        assert str(int(result.risk_score)) in report

    def test_contains_findings(self):
        result, email = _sample_result()
        report = generate_html_report(result, email)
        assert "Return-Path domain mismatch" in report

    def test_contains_css(self):
        result, email = _sample_result()
        report = generate_html_report(result, email)
        assert "<style>" in report


class TestUserReport:
    def test_contains_verdict(self):
        result, email = _sample_result()
        report = generate_user_report(result, email)
        assert "YES" in report or "LIKELY" in report or "POSSIBLY" in report or "PROBABLY NOT" in report

    def test_contains_what_not_to_do(self):
        result, email = _sample_result()
        report = generate_user_report(result, email)
        assert "NOT" in report

    def test_contains_what_to_do(self):
        result, email = _sample_result()
        report = generate_user_report(result, email)
        assert "What You Should Do" in report

    def test_contains_simple_explanation(self):
        result, email = _sample_result()
        report = generate_user_report(result, email)
        assert "Simple Explanation" in report


class TestEmptyReport:
    def test_json_report_with_no_findings(self):
        email = NormalizedEmail(subject="Clean email")
        result = build_analysis_result(email, [])
        report = generate_json_report(result, email)
        data = json.loads(report)
        assert data["risk_score"] == 0.0
        assert len(data["findings"]) == 0

    def test_markdown_report_with_no_findings(self):
        email = NormalizedEmail(subject="Clean email")
        result = build_analysis_result(email, [])
        report = generate_markdown_report(result, email)
        assert "0/100" in report

    def test_user_report_with_no_findings(self):
        email = NormalizedEmail(subject="Clean email")
        result = build_analysis_result(email, [])
        report = generate_user_report(result, email)
        assert "PROBABLY NOT" in report
