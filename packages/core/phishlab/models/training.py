from __future__ import annotations

from pydantic import BaseModel, Field


class TrainingSample(BaseModel):
    id: str
    title: str
    description: str = ""
    eml_filename: str
    is_phishing: bool
    difficulty: str = "beginner"
    explanation: str = ""
    indicators: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class QuizAnswer(BaseModel):
    sample_id: str
    user_answer: bool
    correct: bool = False
    explanation: str = ""
