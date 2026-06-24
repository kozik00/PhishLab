from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from phishlab_api.config import settings


def _get_db_path() -> Path:
    return settings.db_path


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_get_db_path()))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            subject TEXT,
            from_address TEXT,
            risk_score REAL,
            risk_level TEXT,
            findings_json TEXT,
            result_json TEXT,
            email_json TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def store_analysis(
    filename: str,
    subject: str,
    from_address: str,
    risk_score: float,
    risk_level: str,
    findings_json: str,
    result_json: str,
    email_json: str,
) -> str:
    analysis_id = uuid4().hex[:12]
    created_at = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO analyses (id, filename, subject, from_address, risk_score,
                              risk_level, findings_json, result_json, email_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (analysis_id, filename, subject, from_address, risk_score,
         risk_level, findings_json, result_json, email_json, created_at),
    )
    conn.commit()
    conn.close()
    return analysis_id


def get_analysis(analysis_id: str) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return dict(row)


def list_analyses(limit: int = 50, offset: int = 0) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, filename, subject, from_address, risk_score, risk_level, created_at "
        "FROM analyses ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
