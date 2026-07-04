"""Explainable AI response generation."""

from __future__ import annotations

from app.models.detection import DetectorResult


class ExplanationBuilder:
    """Build concise, detector-specific explanations."""

    def build(self, results: list[DetectorResult]) -> list[str]:
        reasons: list[str] = []
        for result in sorted(results, key=lambda item: item.score, reverse=True):
            if result.failed:
                reasons.append(f"{result.detector_name} detector failed: {result.error}")
                continue
            reasons.extend(result.evidence)
        return list(dict.fromkeys(reason for reason in reasons if reason))

