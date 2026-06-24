from __future__ import annotations

import os
from pathlib import Path


class Settings:
    host: str = os.getenv("PHISHLAB_HOST", "127.0.0.1")
    port: int = int(os.getenv("PHISHLAB_PORT", "8000"))
    debug: bool = os.getenv("PHISHLAB_DEBUG", "true").lower() == "true"
    db_path: Path = Path(os.getenv("PHISHLAB_DB_PATH", "./phishlab.db"))
    max_upload_size_mb: int = int(os.getenv("PHISHLAB_MAX_UPLOAD_SIZE_MB", "10"))
    upload_dir: Path = Path(os.getenv("PHISHLAB_UPLOAD_DIR", "./uploads"))
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]


settings = Settings()
