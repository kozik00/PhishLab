from __future__ import annotations

from phishlab_api.config import settings

MAX_UPLOAD_BYTES = settings.max_upload_size_mb * 1024 * 1024
ALLOWED_EXTENSIONS = {".eml"}
