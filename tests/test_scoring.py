from __future__ import annotations

from phishlab.models.analysis import RiskLevel
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Category, Finding, Severity
from phishlab.scoring.risk_score import (
    build_analysis_result,
    calculate_category_scores,
    calculate_risk_score,
    determine_risk_level,
    get_top_contributors,
)


def _finding(severity: Severity, category: Category = Category.CONTENT, title: str = "Test") -> Finding:
    return Finding(title=title, category=category, severity=severity)


class TestCalculateRiskScore:
    def test_empty_findings_returns_zero(self):
        assert calculate_risk_score([]) == 0.0

    def test_single_critical_scores_35(self):
        assert calculate_risk_score([_finding(Severity.CRITICAL)]) == 35.0

    def test_single_high_scores_20(self):
        assert calculate_risk_score([_finding(Severity.HIGH)]) == 20.0

    def test_single_medium_scores_10(self):
        assert calculate_risk_score([_finding(Severity.MEDIUM)]) == 10.0

    def test_single_low_scores_4(self):
        assert calculate_risk_score([_finding(Severity.LOW)]) == 4.0

    def test_single_info_scores_0(self):
        assert calculate_risk_score([_finding(Severity.INFO)]) == 0.0

    def test_caps_at_100(self):
        findings = [_finding(Severity.CRITICAL)] * 5
        assert calculate_risk_score(findings) == 100.0

    def test_mixed_severities(self):
        findings = [
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
        ]
        assert calculate_risk_score(findings) == 34.0

    def test_many_low_findings_accumulate(self):
        findings = [_finding(Severity.LOW)] * 10
        assert calculate_risk_score(findings) == 40.0


class TestDetermineRiskLevel:
    def test_zero_is_low(self):
        assert determine_risk_level(0) == RiskLevel.LOW

    def test_30_is_low(self):
        assert determine_risk_level(30) == RiskLevel.LOW

    def test_31_is_medium(self):
        assert determine_risk_level(31) == RiskLevel.MEDIUM

    def test_60_is_medium(self):
        assert determine_risk_level(60) == RiskLevel.MEDIUM

    def test_61_is_high(self):
        assert determine_risk_level(61) == RiskLevel.HIGH

    def test_80_is_high(self):
        assert determine_risk_level(80) == RiskLevel.HIGH

    def test_81_is_critical(self):
        assert determine_risk_level(81) == RiskLevel.CRITICAL

    def test_100_is_critical(self):
        assert determine_risk_level(100) == RiskLevel.CRITICAL


class TestCategoryScores:
    def test_groups_by_category(self):
        findings = [
            _finding(Severity.HIGH, Category.LINKS, "Link issue"),
            _finding(Severity.MEDIUM, Category.LINKS, "Another link issue"),
            _finding(Severity.HIGH, Category.AUTHENTICATION, "Auth issue"),
        ]
        scores = calculate_category_scores(findings)
        categories = {s.category for s in scores}
        assert "links" in categories
        assert "authentication" in categories

    def test_category_score_sums_points(self):
        findings = [
            _finding(Severity.HIGH, Category.LINKS),
            _finding(Severity.MEDIUM, Category.LINKS),
        ]
        scores = calculate_category_scores(findings)
        link_score = next(s for s in scores if s.category == "links")
        assert link_score.score == 30.0
        assert link_score.finding_count == 2

    def test_empty_findings_returns_empty(self):
        assert calculate_category_scores([]) == []


class TestTopContributors:
    def test_returns_highest_severity_first(self):
        findings = [
            _finding(Severity.LOW, title="Low finding"),
            _finding(Severity.CRITICAL, title="Critical finding"),
            _finding(Severity.MEDIUM, title="Medium finding"),
        ]
        top = get_top_contributors(findings, limit=2)
        assert top[0] == "Critical finding"
        assert len(top) == 2

    def test_respects_limit(self):
        findings = [_finding(Severity.HIGH, title=f"Finding {i}") for i in range(10)]
        top = get_top_contributors(findings, limit=3)
        assert len(top) == 3

    def test_empty_findings_returns_empty(self):
        assert get_top_contributors([]) == []


class TestBuildAnalysisResult:
    def test_builds_complete_result(self):
        email = NormalizedEmail(
            message_id="<test@example.com>",
            subject="Test Email",
            from_address="sender@example.com",
        )
        findings = [
            _finding(Severity.HIGH, Category.LINKS, "Bad link"),
            _finding(Severity.MEDIUM, Category.CONTENT, "Urgency"),
        ]
        result = build_analysis_result(email, findings)

        assert result.email_id == "<test@example.com>"
        assert result.subject == "Test Email"
        assert result.from_address == "sender@example.com"
        assert result.risk_score == 30.0
        assert result.risk_level == RiskLevel.LOW
        assert len(result.findings) == 2
        assert len(result.category_scores) == 2
        assert len(result.top_contributors) == 2

    def test_empty_findings_produces_zero_score(self):
        email = NormalizedEmail()
        result = build_analysis_result(email, [])
        assert result.risk_score == 0.0
        assert result.risk_level == RiskLevel.LOW
