from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from phishlab.models.analysis import AnalysisResult
from phishlab.models.email import NormalizedEmail
from phishlab.reports.generator import (
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    generate_user_report,
)
from phishlab_api.database import get_analysis

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/analyses/{analysis_id}/report")
async def get_report(
    analysis_id: str,
    format: str = Query("json", pattern="^(json|markdown|html|user)$"),
):
    row = get_analysis(analysis_id)
    if row is None:
        raise HTTPException(404, "Analysis not found")

    result = AnalysisResult.model_validate_json(row["result_json"])
    email = NormalizedEmail.model_validate_json(row["email_json"])

    if format == "json":
        report = generate_json_report(result, email)
        return Response(
            content=report,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=phishlab-report-{analysis_id}.json"},
        )
    elif format == "markdown":
        report = generate_markdown_report(result, email)
        return PlainTextResponse(
            content=report,
            headers={"Content-Disposition": f"attachment; filename=phishlab-report-{analysis_id}.md"},
        )
    elif format == "html":
        report = generate_html_report(result, email)
        return HTMLResponse(
            content=report,
            headers={"Content-Disposition": f"attachment; filename=phishlab-report-{analysis_id}.html"},
        )
    elif format == "user":
        report = generate_user_report(result, email)
        return PlainTextResponse(
            content=report,
            headers={"Content-Disposition": f"attachment; filename=phishlab-user-report-{analysis_id}.md"},
        )
