"""DNS detector."""

from __future__ import annotations

import asyncio
import socket

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class DNSDetector(BaseDetector):
    name = "dns"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        evidence: list[str] = []
        metadata = {"resolved": False, "addresses": []}
        score = 0.0
        try:
            loop = asyncio.get_running_loop()
            infos = await loop.run_in_executor(None, socket.getaddrinfo, context.hostname, None)
            addresses = sorted({info[4][0] for info in infos})
            metadata = {"resolved": True, "addresses": addresses, "address_count": len(addresses)}
            if not addresses:
                score = 20.0
                evidence.append("Domain did not resolve")
        except Exception as exc:
            score = 20.0
            evidence.append("DNS lookup failed")
            metadata["error"] = str(exc)
        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=0.6,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata=metadata,
        )

