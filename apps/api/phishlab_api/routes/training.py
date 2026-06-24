from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from phishlab.parser.eml_parser import parse_eml_file
from phishlab.analyzers.orchestrator import run_analysis
from phishlab.scoring.risk_score import build_analysis_result
from phishlab.training.library import (
    get_sample_by_id,
    get_sample_eml_path,
    load_training_samples,
)
from phishlab.training.quiz import calculate_quiz_score, evaluate_answer

router = APIRouter(prefix="/api/training", tags=["training"])


@router.get("/samples")
async def list_samples():
    samples = load_training_samples()
    return [
        {
            "id": s.id,
            "title": s.title,
            "description": s.description,
            "difficulty": s.difficulty,
            "tags": s.tags,
        }
        for s in samples
    ]


@router.get("/samples/{sample_id}")
async def get_sample(sample_id: str):
    sample = get_sample_by_id(sample_id)
    if sample is None:
        raise HTTPException(404, "Training sample not found")

    eml_path = get_sample_eml_path(sample)
    if not eml_path.exists():
        raise HTTPException(500, "Sample .eml file missing")

    email = parse_eml_file(eml_path)

    return {
        "id": sample.id,
        "title": sample.title,
        "description": sample.description,
        "difficulty": sample.difficulty,
        "tags": sample.tags,
        "email": {
            "subject": email.subject,
            "from_address": email.from_address,
            "from_display_name": email.from_display_name,
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "to": email.to,
            "date_raw": email.date_raw,
            "text_body": email.text_body,
            "authentication_results": email.authentication_results,
            "link_count": len(email.links),
            "attachment_count": len(email.attachments),
            "links": [
                {
                    "visible_text": l.visible_text,
                    "href": l.href,
                    "domain": l.domain,
                    "is_ip_based": l.is_ip_based,
                    "is_shortened": l.is_shortened,
                    "uses_https": l.uses_https,
                }
                for l in email.links
            ],
            "attachments": [
                {
                    "filename": a.filename,
                    "extension": a.extension,
                    "size_bytes": a.size_bytes,
                    "has_double_extension": a.has_double_extension,
                    "is_suspicious_type": a.is_suspicious_type,
                }
                for a in email.attachments
            ],
        },
    }


@router.get("/samples/{sample_id}/analysis")
async def get_sample_analysis(sample_id: str):
    sample = get_sample_by_id(sample_id)
    if sample is None:
        raise HTTPException(404, "Training sample not found")

    eml_path = get_sample_eml_path(sample)
    if not eml_path.exists():
        raise HTTPException(500, "Sample .eml file missing")

    email = parse_eml_file(eml_path)
    findings = run_analysis(email)
    result = build_analysis_result(email, findings)

    return {
        "id": sample.id,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level.value,
        "finding_count": len(result.findings),
        "findings": [f.model_dump() for f in result.findings],
        "category_scores": [cs.model_dump() for cs in result.category_scores],
        "top_contributors": result.top_contributors,
    }


class AnswerRequest(BaseModel):
    sample_id: str
    user_answer: bool


@router.post("/answer")
async def submit_answer(req: AnswerRequest):
    result = evaluate_answer(req.sample_id, req.user_answer)

    sample = get_sample_by_id(req.sample_id)
    indicators = sample.indicators if sample else []

    return {
        "sample_id": result.sample_id,
        "user_answer": result.user_answer,
        "correct": result.correct,
        "explanation": result.explanation,
        "indicators": indicators,
    }


class QuizRequest(BaseModel):
    answers: dict[str, bool]


@router.post("/quiz")
async def submit_quiz(req: QuizRequest):
    results = [evaluate_answer(sid, ans) for sid, ans in req.answers.items()]
    score = calculate_quiz_score(results)

    return {
        "score": score,
        "results": [
            {
                "sample_id": r.sample_id,
                "user_answer": r.user_answer,
                "correct": r.correct,
                "explanation": r.explanation,
            }
            for r in results
        ],
    }
