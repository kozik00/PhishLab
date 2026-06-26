from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from phishlab.integrations.virustotal import VirusTotalClient, VTResult, _url_to_vt_id
from phishlab.integrations.url_reputation import SafeBrowsingClient, URLReputationResult


class TestVTResult:
    def test_is_malicious_when_3_plus(self):
        r = VTResult(resource="x", found=True, malicious=3, total=70)
        assert r.is_malicious is True

    def test_not_malicious_when_2(self):
        r = VTResult(resource="x", found=True, malicious=2, total=70)
        assert r.is_malicious is False

    def test_is_suspicious_when_1_malicious(self):
        r = VTResult(resource="x", found=True, malicious=1, total=70)
        assert r.is_suspicious is True

    def test_not_suspicious_when_clean(self):
        r = VTResult(resource="x", found=True, malicious=0, suspicious=0, total=70)
        assert r.is_suspicious is False

    def test_detection_ratio(self):
        r = VTResult(resource="x", found=True, malicious=5, total=70)
        assert r.detection_ratio == "5/70"

    def test_detection_ratio_zero(self):
        r = VTResult(resource="x", found=True)
        assert r.detection_ratio == "0/0"


class TestVTClient:
    def test_requires_api_key(self):
        with pytest.raises(ValueError):
            VirusTotalClient("")

    def test_requires_nonempty_key(self):
        with pytest.raises(ValueError):
            VirusTotalClient("   ")

    @patch("phishlab.integrations.virustotal.urllib.request.urlopen")
    def test_check_domain_malicious(self, mock_urlopen):
        response_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 4,
                    },
                    "reputation": -10,
                    "categories": {"vendor1": "phishing"},
                }
            }
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = VirusTotalClient("test-key")
        client._last_request = 0
        result = client.check_domain("evil.com")

        assert result.found is True
        assert result.is_malicious is True
        assert result.malicious == 5

    @patch("phishlab.integrations.virustotal.urllib.request.urlopen")
    def test_check_domain_not_found(self, mock_urlopen):
        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError(
            url="", code=404, msg="Not Found", hdrs=None, fp=None
        )

        client = VirusTotalClient("test-key")
        client._last_request = 0
        result = client.check_domain("unknown.com")

        assert result.found is False

    def test_url_to_vt_id(self):
        vid = _url_to_vt_id("https://example.com")
        assert isinstance(vid, str)
        assert len(vid) > 0


class TestURLReputationResult:
    def test_is_dangerous_with_threats(self):
        r = URLReputationResult(url="x", safe=False, threats=["MALWARE"])
        assert r.is_dangerous is True

    def test_not_dangerous_when_safe(self):
        r = URLReputationResult(url="x", safe=True)
        assert r.is_dangerous is False


class TestSafeBrowsingClient:
    def test_requires_api_key(self):
        with pytest.raises(ValueError):
            SafeBrowsingClient("")

    def test_empty_urls_returns_empty(self):
        client = SafeBrowsingClient("test-key")
        results = client.check_urls([])
        assert results == []

    @patch("phishlab.integrations.url_reputation.urllib.request.urlopen")
    def test_check_urls_safe(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({}).encode()
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = SafeBrowsingClient("test-key")
        results = client.check_urls(["https://example.com"])

        assert len(results) == 1
        assert results[0].safe is True

    @patch("phishlab.integrations.url_reputation.urllib.request.urlopen")
    def test_check_urls_dangerous(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "matches": [
                {
                    "threat": {"url": "https://evil.com"},
                    "threatType": "SOCIAL_ENGINEERING",
                }
            ]
        }).encode()
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = SafeBrowsingClient("test-key")
        results = client.check_urls(["https://evil.com", "https://safe.com"])

        assert len(results) == 2
        evil = next(r for r in results if r.url == "https://evil.com")
        safe = next(r for r in results if r.url == "https://safe.com")
        assert evil.is_dangerous is True
        assert "SOCIAL_ENGINEERING" in evil.threats
        assert safe.safe is True

    @patch("phishlab.integrations.url_reputation.urllib.request.urlopen")
    def test_check_url_single(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({}).encode()
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        client = SafeBrowsingClient("test-key")
        result = client.check_url("https://example.com")

        assert result.safe is True
