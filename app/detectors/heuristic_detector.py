"""URL heuristic detector."""

from __future__ import annotations

import re

from app.config.constants import RISKY_TLDS, SUSPICIOUS_KEYWORDS
from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class HeuristicDetector(BaseDetector):
    name = "heuristic"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        evidence: list[str] = []
        score = 0.0
        lower_url = context.canonical_url.lower()
        suffix = context.registered_domain.rsplit(".", 1)[-1] if "." in context.registered_domain else ""

        if suffix in RISKY_TLDS:
            score += 20
            evidence.append("Suspicious top-level domain")
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", context.hostname):
            score += 25
            evidence.append("IP address used as hostname")
        if "@" in context.canonical_url:
            score += 15
            evidence.append("@ symbol in URL")
        hits = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lower_url]
        if hits:
            score += min(30, 8 * len(hits))
            evidence.append(f"Suspicious URL keywords: {', '.join(sorted(hits))}")
        if len(context.canonical_url) > 100:
            score += 10
            evidence.append("Unusually long URL")

        score = min(score, 100.0)
        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=0.75 if evidence else 0.4,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata={"registered_domain": context.registered_domain},
        )

