"""URL reputation checking using Google Safe Browsing Lookup API (v4).

Opt-in only — requires a Google Safe Browsing API key.
Only sends the URL being checked. No other email data is transmitted.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field


THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]

THREAT_ENTRY_TYPES = ["URL"]


@dataclass
class URLReputationResult:
    url: str
    safe: bool
    threats: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def is_dangerous(self) -> bool:
        return not self.safe and len(self.threats) > 0


class SafeBrowsingClient:
    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key: str):
        if not api_key or not api_key.strip():
            raise ValueError("Google Safe Browsing API key is required")
        self._api_key = api_key.strip()

    def check_urls(self, urls: list[str]) -> list[URLReputationResult]:
        if not urls:
            return []

        batch = urls[:500]

        body = json.dumps({
            "client": {
                "clientId": "phishlab",
                "clientVersion": "0.2.0",
            },
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": PLATFORM_TYPES,
                "threatEntryTypes": THREAT_ENTRY_TYPES,
                "threatEntries": [{"url": u} for u in batch],
            },
        }).encode()

        req = urllib.request.Request(
            f"{self.API_URL}?key={self._api_key}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            error_msg = f"Safe Browsing API error: {e.code}"
            return [
                URLReputationResult(url=u, safe=True, error=error_msg)
                for u in batch
            ]
        except urllib.error.URLError as e:
            error_msg = f"Network error: {e.reason}"
            return [
                URLReputationResult(url=u, safe=True, error=error_msg)
                for u in batch
            ]

        threat_map: dict[str, list[str]] = {}
        for match in data.get("matches", []):
            url = match.get("threat", {}).get("url", "")
            threat_type = match.get("threatType", "UNKNOWN")
            if url not in threat_map:
                threat_map[url] = []
            threat_map[url].append(threat_type)

        results = []
        for url in batch:
            threats = threat_map.get(url, [])
            results.append(URLReputationResult(
                url=url,
                safe=len(threats) == 0,
                threats=threats,
            ))

        return results

    def check_url(self, url: str) -> URLReputationResult:
        results = self.check_urls([url])
        return results[0] if results else URLReputationResult(
            url=url, safe=True, error="No result"
        )
