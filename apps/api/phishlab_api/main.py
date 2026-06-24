from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from phishlab_api.config import settings
from phishlab_api.database import init_db
from phishlab_api.routes.analysis import router as analysis_router
from phishlab_api.routes.reports import router as reports_router
from phishlab_api.routes.training import router as training_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="PhishLab API",
    description="Local-first Email Threat Analysis and Phishing Awareness Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analysis_router)
app.include_router(reports_router)
app.include_router(training_router)


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": "0.1.0"}
