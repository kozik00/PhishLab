from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["PHISHLAB_DB_PATH"] = str(Path(tempfile.mkdtemp()) / "test.db")
os.environ["PHISHLAB_UPLOAD_DIR"] = tempfile.mkdtemp()

from phishlab_api.main import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def simple_eml() -> bytes:
    return (FIXTURES_DIR / "simple.eml").read_bytes()


@pytest.fixture
def phishing_eml() -> bytes:
    return (FIXTURES_DIR / "phishing_links.eml").read_bytes()


class TestHealthCheck:
    def test_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


class TestAnalyzeEndpoint:
    def test_upload_valid_eml(self, client, simple_eml):
        resp = client.post(
            "/api/analyze",
            files={"file": ("test.eml", simple_eml, "message/rfc822")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert data["subject"] == "Meeting Tomorrow"
        assert data["from_address"] == "john.doe@example.com"
        assert isinstance(data["risk_score"], (int, float))
        assert data["risk_level"] in ("low", "medium", "high", "critical")

    def test_upload_phishing_eml(self, client, phishing_eml):
        resp = client.post(
            "/api/analyze",
            files={"file": ("phish.eml", phishing_eml, "message/rfc822")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_score"] > 30
        assert data["finding_count"] >= 5

    def test_rejects_non_eml(self, client):
        resp = client.post(
            "/api/analyze",
            files={"file": ("test.txt", b"not an email", "text/plain")},
        )
        assert resp.status_code == 400

    def test_rejects_large_file(self, client):
        big = b"X" * (11 * 1024 * 1024)
        resp = client.post(
            "/api/analyze",
            files={"file": ("big.eml", big, "message/rfc822")},
        )
        assert resp.status_code == 413


class TestAnalysesEndpoints:
    def test_list_analyses(self, client, simple_eml):
        client.post(
            "/api/analyze",
            files={"file": ("test.eml", simple_eml, "message/rfc822")},
        )
        resp = client.get("/api/analyses")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_analysis_detail(self, client, simple_eml):
        upload = client.post(
            "/api/analyze",
            files={"file": ("test.eml", simple_eml, "message/rfc822")},
        )
        aid = upload.json()["id"]

        resp = client.get(f"/api/analyses/{aid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == aid
        assert "findings" in data
        assert "result" in data
        assert "email" in data

    def test_get_nonexistent_analysis(self, client):
        resp = client.get("/api/analyses/nonexistent123")
        assert resp.status_code == 404


class TestReportEndpoints:
    def test_json_report(self, client, phishing_eml):
        upload = client.post(
            "/api/analyze",
            files={"file": ("phish.eml", phishing_eml, "message/rfc822")},
        )
        aid = upload.json()["id"]

        resp = client.get(f"/api/analyses/{aid}/report?format=json")
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]

    def test_markdown_report(self, client, phishing_eml):
        upload = client.post(
            "/api/analyze",
            files={"file": ("phish.eml", phishing_eml, "message/rfc822")},
        )
        aid = upload.json()["id"]

        resp = client.get(f"/api/analyses/{aid}/report?format=markdown")
        assert resp.status_code == 200
        assert "PhishLab" in resp.text

    def test_html_report(self, client, phishing_eml):
        upload = client.post(
            "/api/analyze",
            files={"file": ("phish.eml", phishing_eml, "message/rfc822")},
        )
        aid = upload.json()["id"]

        resp = client.get(f"/api/analyses/{aid}/report?format=html")
        assert resp.status_code == 200
        assert "<!DOCTYPE html>" in resp.text

    def test_user_report(self, client, phishing_eml):
        upload = client.post(
            "/api/analyze",
            files={"file": ("phish.eml", phishing_eml, "message/rfc822")},
        )
        aid = upload.json()["id"]

        resp = client.get(f"/api/analyses/{aid}/report?format=user")
        assert resp.status_code == 200
        assert "What You Should" in resp.text

    def test_nonexistent_analysis_report(self, client):
        resp = client.get("/api/analyses/nonexistent123/report?format=json")
        assert resp.status_code == 404


class TestTrainingEndpoints:
    def test_list_samples(self, client):
        resp = client.get("/api/training/samples")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 7
        for s in data:
            assert "id" in s
            assert "title" in s
            assert "difficulty" in s

    def test_get_sample(self, client):
        resp = client.get("/api/training/samples/fake-microsoft-alert")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "fake-microsoft-alert"
        assert "email" in data
        assert data["email"]["subject"]

    def test_get_sample_analysis(self, client):
        resp = client.get("/api/training/samples/fake-microsoft-alert/analysis")
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_score"] > 0
        assert len(data["findings"]) >= 1

    def test_get_nonexistent_sample(self, client):
        resp = client.get("/api/training/samples/nonexistent")
        assert resp.status_code == 404

    def test_submit_correct_answer(self, client):
        resp = client.post(
            "/api/training/answer",
            json={"sample_id": "fake-microsoft-alert", "user_answer": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["correct"] is True
        assert data["explanation"]
        assert len(data["indicators"]) >= 1

    def test_submit_incorrect_answer(self, client):
        resp = client.post(
            "/api/training/answer",
            json={"sample_id": "benign-newsletter", "user_answer": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["correct"] is False

    def test_submit_quiz(self, client):
        resp = client.post(
            "/api/training/quiz",
            json={
                "answers": {
                    "fake-microsoft-alert": True,
                    "benign-newsletter": False,
                    "gift-card-scam": True,
                }
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"]["total"] == 3
        assert data["score"]["correct"] == 3
        assert data["score"]["score_percent"] == 100.0
