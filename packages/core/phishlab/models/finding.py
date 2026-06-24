from __future__ import annotations

from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SENDER_IDENTITY = "sender_identity"
    AUTHENTICATION = "authentication"
    LINKS = "links"
    ATTACHMENTS = "attachments"
    CONTENT = "content"
    BRAND_IMPERSONATION = "brand_impersonation"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    title: str
    category: Category
    severity: Severity
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    location: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)
