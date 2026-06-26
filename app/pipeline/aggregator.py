"""Weighted risk aggregation engine."""

from __future__ import annotations

from app.schemas.detection import DetectorResult


class RiskAggregator:
    """Combine detector scores into a weighted ensemble score."""

    def __init__(self, weights: dict[str, float] | object | None = None) -> None:
        self.weights = self._normalize_weights(weights or {})

    def aggregate(self, results: list[DetectorResult]) -> float:
        usable = [result for result in results if not result.failed]
        if not usable:
            return 0.0
        weighted_sum = 0.0
        total_weight = 0.0
        for result in usable:
            weight = self.weights.get(result.detector_name, 0.05)
            weighted_sum += result.score * result.confidence * weight
            total_weight += result.confidence * weight
        if total_weight == 0:
            return 0.0
        return round(max(0.0, min(weighted_sum / total_weight, 100.0)), 1)

    @staticmethod
    def verdict_for_score(score: float) -> str:
        if score >= 90:
            return "BLOCK"
        if score >= 70:
            return "WARN"
        if score >= 40:
            return "MONITOR"
        return "ALLOW"

    @staticmethod
    def _normalize_weights(weights: dict[str, float] | object) -> dict[str, float]:
        if hasattr(weights, "model_dump"):
            return dict(weights.model_dump())
        if isinstance(weights, dict):
            return dict(weights)
        return dict(getattr(weights, "__dict__", {}))

