from __future__ import annotations

from collections import defaultdict

from phishlab.models.analysis import AnalysisResult, CategoryScore, RiskLevel
from phishlab.models.email import NormalizedEmail
from phishlab.models.finding import Finding, Severity

_SEVERITY_POINTS: dict[Severity, int] = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 0,
}


def calculate_risk_score(findings: list[Finding]) -> float:
    total = sum(_SEVERITY_POINTS[f.severity] for f in findings)
    return min(100.0, float(total))


def determine_risk_level(score: float) -> RiskLevel:
    if score <= 30:
        return RiskLevel.LOW
    if score <= 60:
        return RiskLevel.MEDIUM
    if score <= 80:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def calculate_category_scores(findings: list[Finding]) -> list[CategoryScore]:
    by_category: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_category[f.category.value].append(f)

    scores: list[CategoryScore] = []
    for category, cat_findings in sorted(by_category.items()):
        cat_score = sum(_SEVERITY_POINTS[f.severity] for f in cat_findings)
        scores.append(CategoryScore(
            category=category,
            score=float(cat_score),
            finding_count=len(cat_findings),
        ))

    return scores


def get_top_contributors(findings: list[Finding], limit: int = 5) -> list[str]:
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_POINTS[f.severity],
        reverse=True,
    )
    return [f.title for f in sorted_findings[:limit]]


def build_analysis_result(
    email: NormalizedEmail,
    findings: list[Finding],
) -> AnalysisResult:
    score = calculate_risk_score(findings)
    level = determine_risk_level(score)
    category_scores = calculate_category_scores(findings)
    top_contributors = get_top_contributors(findings)

    return AnalysisResult(
        email_id=email.message_id,
        subject=email.subject,
        from_address=email.from_address,
        findings=findings,
        risk_score=score,
        risk_level=level,
        category_scores=category_scores,
        top_contributors=top_contributors,
    )
