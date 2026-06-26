"""Threat reputation detector."""

from __future__ import annotations

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class ReputationDetector(BaseDetector):
    name = "reputation"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        vt_service = context.services.get("virustotal")
        vt = await vt_service.lookup_url(context.canonical_url) if vt_service else {"checked": False, "malicious": 0, "total": 0}
        evidence = []
        score = 0.0
        confidence = 0.2
        if vt.get("checked") and vt.get("total", 0):
            ratio = vt.get("malicious", 0) / vt["total"]
            score = min(ratio * 100, 100.0)
            confidence = 0.95
            if vt.get("malicious", 0):
                evidence.append(f"VirusTotal malicious detections: {vt['malicious']}/{vt['total']}")
        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=confidence,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata=vt,
        )

