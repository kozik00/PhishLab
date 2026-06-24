FROM python:3.11-slim AS base

WORKDIR /app

RUN addgroup --system phishlab && adduser --system --ingroup phishlab phishlab

COPY packages/core/pyproject.toml packages/core/
COPY packages/core/phishlab/ packages/core/phishlab/
RUN pip install --no-cache-dir -e packages/core

COPY apps/api/pyproject.toml apps/api/
COPY apps/api/phishlab_api/ apps/api/phishlab_api/
RUN pip install --no-cache-dir -e apps/api

COPY rules/ rules/
COPY examples/ examples/

RUN mkdir -p /app/data /app/uploads && chown -R phishlab:phishlab /app/data /app/uploads

USER phishlab

ENV PHISHLAB_HOST=0.0.0.0 \
    PHISHLAB_PORT=8000 \
    PHISHLAB_DB_PATH=/app/data/phishlab.db \
    PHISHLAB_UPLOAD_DIR=/app/uploads

EXPOSE 8000

CMD ["uvicorn", "phishlab_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
