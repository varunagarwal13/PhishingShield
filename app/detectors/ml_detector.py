"""Machine-learning detector adapter."""

from __future__ import annotations

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class MLDetector(BaseDetector):
    name = "ml"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        state = context.app_state
        if not state or not hasattr(state, "rf") or not hasattr(state, "xgb"):
            return DetectorResult(
                detector_name=self.name,
                score=0.0,
                confidence=0.0,
                execution_time=0.0,
                severity=severity_for_score(0),
                evidence=["ML models unavailable"],
                metadata={"available": False},
            )

        feature_service = context.services.get("features")
        feature_columns = context.feature_columns or getattr(state, "FEATURE_COLS", [])
        features = feature_service.extract(context.canonical_url, feature_columns) if feature_service else {}
        values = [[features.get(column, -1) for column in feature_columns]]
        rf_prob = float(state.rf.predict_proba(values)[0][1])
        xgb_prob = float(state.xgb.predict_proba(values)[0][1])
        score = ((rf_prob + xgb_prob) / 2) * 100
        return DetectorResult(
            detector_name=self.name,
            score=round(score, 1),
            confidence=max(rf_prob, xgb_prob),
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=[f"ML ensemble confidence {score:.1f}%"],
            metadata={"rf_score": round(rf_prob * 100, 1), "xgb_score": round(xgb_prob * 100, 1)},
        )

