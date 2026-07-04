"""Detector plugin interface."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.models.detection import DetectorResult, Severity


@dataclass(slots=True)
class DetectorContext:
    """Shared context passed to every detector."""

    url: str
    canonical_url: str
    hostname: str
    registered_domain: str
    app_state: Any = None
    services: dict[str, Any] = field(default_factory=dict)
    feature_columns: list[str] = field(default_factory=list)
    request_options: dict[str, Any] = field(default_factory=dict)
    shared: dict[str, Any] = field(default_factory=dict)


class BaseDetector(ABC):
    """Abstract detector plugin contract."""

    name = "base"
    enabled = True

    async def run(self, context: DetectorContext) -> DetectorResult:
        """Execute the detector and convert failures into detector results."""
        start = time.perf_counter()
        try:
            result = await self.analyze(context)
            result.execution_time = time.perf_counter() - start
            return result
        except Exception as exc:
            return DetectorResult(
                detector_name=self.name,
                score=0.0,
                confidence=0.0,
                execution_time=time.perf_counter() - start,
                severity=Severity.info,
                evidence=[],
                metadata={},
                failed=True,
                error=str(exc),
            )

    @abstractmethod
    async def analyze(self, context: DetectorContext) -> DetectorResult:
        """Analyze a URL and return a detector result."""

    def explain(self, result: DetectorResult) -> list[str]:
        """Return human-readable explanations from detector evidence."""
        return result.evidence

    async def health_check(self) -> dict[str, Any]:
        """Return detector health status."""
        return {"detector": self.name, "status": "ok", "enabled": self.enabled}


def severity_for_score(score: float) -> Severity:
    if score >= 90:
        return Severity.critical
    if score >= 70:
        return Severity.high
    if score >= 40:
        return Severity.medium
    if score > 0:
        return Severity.low
    return Severity.info

