from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, UploadFile

from phishlab.analyzers.orchestrator import run_analysis
from phishlab.models.email import NormalizedEmail
from phishlab.parser.eml_parser import parse_eml
from phishlab.scoring.risk_score import build_analysis_result
from phishlab_api.config import settings
from phishlab_api.database import get_analysis, list_analyses, store_analysis
from phishlab_api.dependencies import ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES

router = APIRouter(prefix="/api", tags=["analysis"])


@router.post("/analyze")
async def analyze_email(file: UploadFile):
    if not file.filename:
        raise HTTPException(400, "No filename provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Only .eml files are accepted, got '{ext}'")

    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            413,
            f"File too large. Maximum size is {settings.max_upload_size_mb} MB",
        )

    email = parse_eml(content)
    findings = run_analysis(email)
    result = build_analysis_result(email, findings)

    safe_filename = f"{uuid4().hex[:12]}.eml"
    upload_dir = settings.upload_dir
    upload_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / safe_filename).write_bytes(content)

    result_json = result.model_dump_json()
    email_json = email.model_dump_json()
    findings_json = json.dumps([f.model_dump() for f in findings], default=str)

    analysis_id = store_analysis(
        filename=file.filename,
        subject=email.subject,
        from_address=email.from_address,
        risk_score=result.risk_score,
        risk_level=result.risk_level.value,
        findings_json=findings_json,
        result_json=result_json,
        email_json=email_json,
    )

    return {
        "id": analysis_id,
        "filename": file.filename,
        "subject": email.subject,
        "from_address": email.from_address,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level.value,
        "finding_count": len(findings),
        "top_contributors": result.top_contributors,
    }


@router.get("/analyses")
async def get_analyses(limit: int = 50, offset: int = 0):
    return list_analyses(limit=limit, offset=offset)


@router.get("/analyses/{analysis_id}")
async def get_analysis_detail(analysis_id: str):
    row = get_analysis(analysis_id)
    if row is None:
        raise HTTPException(404, "Analysis not found")

    return {
        "id": row["id"],
        "filename": row["filename"],
        "subject": row["subject"],
        "from_address": row["from_address"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "created_at": row["created_at"],
        "findings": json.loads(row["findings_json"]),
        "result": json.loads(row["result_json"]),
        "email": json.loads(row["email_json"]),
    }
