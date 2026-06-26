"""VirusTotal integration for URL and file hash reputation checks.

Opt-in only — requires a VT API key. Free tier: 4 requests/minute, 500/day.
All requests go through a single function with rate limiting.
No data is sent except the URL or hash being queried.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from urllib.parse import quote

import urllib.request
import urllib.error
import json


@dataclass
class VTResult:
    resource: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    reputation_score: int = 0
    categories: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def is_malicious(self) -> bool:
        return self.malicious >= 3

    @property
    def is_suspicious(self) -> bool:
        return self.malicious >= 1 or self.suspicious >= 2

    @property
    def detection_ratio(self) -> str:
        if self.total == 0:
            return "0/0"
        return f"{self.malicious}/{self.total}"


class VirusTotalClient:
    API_BASE = "https://www.virustotal.com/api/v3"
    MIN_REQUEST_INTERVAL = 15.0

    def __init__(self, api_key: str):
        if not api_key or not api_key.strip():
            raise ValueError("VirusTotal API key is required")
        self._api_key = api_key.strip()
        self._last_request: float = 0

    def _rate_limit(self):
        elapsed = time.time() - self._last_request
        if elapsed < self.MIN_REQUEST_INTERVAL:
            time.sleep(self.MIN_REQUEST_INTERVAL - elapsed)
        self._last_request = time.time()

    def _request(self, path: str) -> dict | None:
        self._rate_limit()
        url = f"{self.API_BASE}{path}"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", self._api_key)
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
        except urllib.error.URLError:
            return None

    def check_url(self, url: str) -> VTResult:
        url_id = _url_to_vt_id(url)
        data = self._request(f"/urls/{url_id}")

        if data is None:
            return VTResult(resource=url, found=False)

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        categories_raw = data.get("data", {}).get("attributes", {}).get("categories", {})
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)

        return VTResult(
            resource=url,
            found=True,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=sum(stats.values()) if stats else 0,
            reputation_score=reputation,
            categories=list(categories_raw.values()) if categories_raw else [],
        )

    def check_hash(self, sha256: str) -> VTResult:
        data = self._request(f"/files/{sha256}")

        if data is None:
            return VTResult(resource=sha256, found=False)

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)
        tags = data.get("data", {}).get("attributes", {}).get("tags", [])

        return VTResult(
            resource=sha256,
            found=True,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=sum(stats.values()) if stats else 0,
            reputation_score=reputation,
            categories=tags[:10],
        )

    def check_domain(self, domain: str) -> VTResult:
        data = self._request(f"/domains/{domain}")

        if data is None:
            return VTResult(resource=domain, found=False)

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        categories_raw = data.get("data", {}).get("attributes", {}).get("categories", {})
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)

        return VTResult(
            resource=domain,
            found=True,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total=sum(stats.values()) if stats else 0,
            reputation_score=reputation,
            categories=list(categories_raw.values()) if categories_raw else [],
        )


def _url_to_vt_id(url: str) -> str:
    import base64
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
