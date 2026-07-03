"""VirusTotal adapter."""

from __future__ import annotations

import base64


class VirusTotalService:
    """Async VirusTotal URL lookup with failure isolation."""

    def __init__(self, api_key: str = "", timeout_seconds: float = 5.0) -> None:
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    async def lookup_url(self, url: str) -> dict:
        if not self.api_key:
            return {"checked": False, "malicious": 0, "total": 0}
        try:
            import aiohttp

            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": self.api_key},
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                ) as response:
                    if response.status != 200:
                        return {"checked": False, "malicious": 0, "total": 0, "status": response.status}
                    data = await response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {"checked": True, "malicious": stats.get("malicious", 0), "total": sum(stats.values())}
        except Exception as exc:
            return {"checked": False, "malicious": 0, "total": 0, "error": str(exc)}

