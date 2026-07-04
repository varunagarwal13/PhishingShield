"""URL Analysis detector: predicts phishing probability using LightGBM and explainable reasoners."""

from __future__ import annotations

import logging
import numpy as np

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.models.detection import DetectorResult
from app.ai.loaders import ModelLoader
from app.ai.explainability import generate_lexical_explanations
from training.feature_engineering.features import extract_url_features, FEATURE_COLUMNS

logger = logging.getLogger("url_analysis")


class UrlAnalysisDetector(BaseDetector):
    name = "url_analysis"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        url = context.canonical_url
        
        # 1. Extract URL features
        features = extract_url_features(url)
        
        # 2. Get lazy loaded LightGBM model
        model = ModelLoader.get_structured_model()
        
        score = 0.0
        confidence = 0.5
        evidence = []

        if model is not None:
            try:
                # Convert features to matching matrix shape
                from app.ai.versioning.registry import ModelRegistry
                schema = ModelRegistry.get_feature_schema() or FEATURE_COLUMNS
                vector = [features[col] for col in schema]
                X = np.array([vector], dtype=np.float32)
                
                # Calibrated model predict_proba returns [prob_benign, prob_malicious]
                prob = float(model.predict_proba(X)[0][1])
                score = prob * 100.0
                confidence = 0.90
                evidence.append(f"Structured LightGBM model predicted {score:.1f}% phishing probability")
            except Exception as e:
                logger.error(f"Structured model prediction failed: {e}")
                model = None  # Force fallback on failure


        # Fallback heuristic rules if model is not available
        if model is None:
            logger.info("Structured model fallback: using rule-based scoring")
            heuristic_score = 0.0
            
            if features.get("has_ip", 0.0) == 1.0:
                heuristic_score += 35.0
            if features.get("brand_similarity_score", 0.0) >= 0.7:
                heuristic_score += 40.0
            if features.get("entropy", 0.0) > 3.8:
                heuristic_score += 15.0
            if features.get("suspicious_tld", 0.0) == 1.0:
                heuristic_score += 20.0
            if features.get("suspicious_keyword_count", 0.0) > 0:
                heuristic_score += min(features["suspicious_keyword_count"] * 10.0, 30.0)
                
            score = min(heuristic_score, 100.0)
            confidence = 0.65

        # 3. Generate human explanations from features
        lexical_reasons = generate_lexical_explanations(features)
        evidence.extend(lexical_reasons)

        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=confidence,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata={
                "features": features,
                "model_driven": model is not None
            }
        )
