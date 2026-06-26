"""Optional threat-intelligence adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ThreatIntelResult:
    provider: str
    checked: bool
    malicious: bool = False
    score: float = 0.0
    metadata: dict[str, Any] | None = None
    error: str | None = None


class ThreatIntelAdapter:
    """Base adapter for optional external threat-intelligence providers."""

    provider = "base"

    def __init__(self, api_key: str = "", enabled: bool = False) -> None:
        self.api_key = api_key
        self.enabled = enabled

    async def lookup(self, url: str) -> ThreatIntelResult:
        if not self.enabled:
            return ThreatIntelResult(provider=self.provider, checked=False, metadata={"enabled": False})
        return ThreatIntelResult(provider=self.provider, checked=False, metadata={"status": "adapter_ready"})


class GoogleSafeBrowsingAdapter(ThreatIntelAdapter):
    provider = "google_safe_browsing"


class OpenPhishAdapter(ThreatIntelAdapter):
    provider = "openphish"


class PhishTankAdapter(ThreatIntelAdapter):
    provider = "phishtank"


class URLHausAdapter(ThreatIntelAdapter):
    provider = "urlhaus"


class AbuseIPDBAdapter(ThreatIntelAdapter):
    provider = "abuseipdb"


class CloudflareRadarAdapter(ThreatIntelAdapter):
    provider = "cloudflare_radar"

