"""Favicon similarity detector placeholder."""

from __future__ import annotations

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class FaviconDetector(BaseDetector):
    name = "favicon"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        return DetectorResult(
            detector_name=self.name,
            score=0.0,
            confidence=0.2,
            execution_time=0.0,
            severity=severity_for_score(0),
            evidence=[],
            metadata={"status": "favicon_similarity_adapter_ready"},
        )

