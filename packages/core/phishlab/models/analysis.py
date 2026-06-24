from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from phishlab.models.finding import Finding


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CategoryScore(BaseModel):
    category: str
    score: float = 0.0
    finding_count: int = 0


class AnalysisResult(BaseModel):
    email_id: str = ""
    subject: str = ""
    from_address: str = ""
    findings: list[Finding] = Field(default_factory=list)
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    category_scores: list[CategoryScore] = Field(default_factory=list)
    top_contributors: list[str] = Field(default_factory=list)
