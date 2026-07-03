"""WHOIS age detector."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class WhoisDetector(BaseDetector):
    name = "whois"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        loop = asyncio.get_running_loop()
        try:
            age_days = await loop.run_in_executor(None, self._domain_age_days, context.registered_domain)
        except Exception as exc:
            return DetectorResult(
                detector_name=self.name,
                score=0.0,
                confidence=0.1,
                execution_time=0.0,
                severity=severity_for_score(0),
                evidence=[],
                metadata={"available": False, "error": str(exc)},
            )
        evidence = []
        score = 0.0
        if age_days < 30:
            score = 35.0
            evidence.append("Domain age less than 30 days")
        elif age_days < 90:
            score = 15.0
            evidence.append("Recently registered domain")
        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=0.7,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata={"domain_age_days": age_days, "available": True},
        )

    @staticmethod
    def _domain_age_days(domain: str) -> int:
        import whois

        data = whois.whois(domain)
        created = data.creation_date[0] if isinstance(data.creation_date, list) else data.creation_date
        if created is None:
            raise ValueError("WHOIS response did not include creation date")
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - created).days)

