"""SSL certificate detector."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class SSLDetector(BaseDetector):
    name = "ssl"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        if not context.canonical_url.startswith("https://"):
            return DetectorResult(
                detector_name=self.name,
                score=25.0,
                confidence=0.8,
                execution_time=0.0,
                severity=severity_for_score(25.0),
                evidence=["No HTTPS"],
                metadata={"valid": False},
            )
        loop = asyncio.get_running_loop()
        try:
            cert = await loop.run_in_executor(None, self._get_certificate, context.hostname)
            expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (expires - datetime.now(timezone.utc)).days
            evidence = []
            score = 0.0
            if days_remaining < 7:
                score = 20.0
                evidence.append("SSL certificate expires soon")
            return DetectorResult(
                detector_name=self.name,
                score=score,
                confidence=0.8,
                execution_time=0.0,
                severity=severity_for_score(score),
                evidence=evidence,
                metadata={"valid": True, "days_remaining": days_remaining},
            )
        except Exception as exc:
            return DetectorResult(
                detector_name=self.name,
                score=30.0,
                confidence=0.6,
                execution_time=0.0,
                severity=severity_for_score(30.0),
                evidence=["SSL certificate validation failed"],
                metadata={"valid": False, "error": str(exc)},
            )

    @staticmethod
    def _get_certificate(hostname: str) -> dict:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                return tls.getpeercert()

