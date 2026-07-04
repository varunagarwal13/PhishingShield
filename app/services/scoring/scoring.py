"""Meta-Risk Scoring Engine: Calibrated weighted average of active detectors."""

from __future__ import annotations

import logging
from config.settings import get_settings

logger = logging.getLogger("scoring")

# Target weights for all 7 detectors (must sum to 1.0)
DETECTOR_WEIGHTS = {
    "url_analysis": 0.20,
    "threat_intelligence": 0.25,
    "visual_hash": 0.15,
    "content_analysis": 0.15,
    "javascript_intelligence": 0.10,
    "browser_behavior": 0.08,
    "image_analysis": 0.07
}


class ScoringService:
    """Combines sub-detector risk outputs into a final calibrated risk scorecard."""

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or DETECTOR_WEIGHTS

    def compute_score(self, detector_outputs: dict[str, dict], fast_checks: dict) -> dict:
        """Dynamically scales weights based on active/executed detectors and computes a global score."""
        active_weights_sum = 0.0
        weighted_score = 0.0
        signals = []
        all_signals = []

        # 1. Parse active detectors
        for detector_name, out in detector_outputs.items():
            if not out or out.get("metadata", {}).get("status") == "no_screenshot_available":
                continue
            
            w = self.weights.get(detector_name, 0.0)
            sub_score = out.get("score", 0.0)
            sub_signals = out.get("signals", []) or out.get("evidence", [])

            weighted_score += sub_score * w
            active_weights_sum += w
            
            if sub_signals:
                signals.extend(sub_signals[:2])
                all_signals.extend(sub_signals)

        # Scale dynamically if some detectors were skipped
        if active_weights_sum > 0:
            final_detector_score = weighted_score / active_weights_sum
        else:
            final_detector_score = 0.0

        # 2. Incorporate Fast Checks contributions
        fast_score = float(fast_checks.get("partial_score", 0))
        fast_signals = fast_checks.get("signals", [])
        all_signals.extend(fast_signals)
        if fast_signals:
            signals.extend(fast_signals[:2])

        # Composite score calculation (Fast check acts as a base offset or primary indicator)
        # Standard calibration: max of detectors score and fast checks score
        final_score = max(final_detector_score, fast_score)
        final_score = min(max(final_score, 0.0), 100.0)

        # Deduplicate signals list
        signals = list(dict.fromkeys(sig for sig in signals if sig))
        all_signals = list(dict.fromkeys(sig for sig in all_signals if sig))

        # 3. Determine final verdict Action
        import json
        from pathlib import Path
        meta_path = Path("training/export/model_metadata.json")
        opt_threshold = 0.40
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                opt_threshold = float(meta.get("optimal_threshold", 0.40))
            except Exception:
                pass

        block_t = opt_threshold * 100.0
        warn_t = block_t * 0.7

        if final_score >= block_t:
            action = "block"
        elif final_score >= warn_t:
            action = "warn"
        else:
            action = "allow"

        # Calculate average confidence of active detectors
        active_confidences = [
            out.get("confidence", 0.5) for out in detector_outputs.values()
            if out and out.get("metadata", {}).get("status") != "no_screenshot_available"
        ]
        confidence = sum(active_confidences) / len(active_confidences) if active_confidences else 0.5

        return {
            "action": action,
            "score": round(final_score, 1),
            "confidence": round(confidence, 2),
            "signals": signals[:4],
            "all_signals": all_signals,
            "details": {
                "active_detectors": [k for k in detector_outputs if detector_outputs[k]],
                "detector_score": round(final_detector_score, 1),
                "fast_check_score": fast_score
            }
        }

    def _make_verdict(self, score: float, signals: list[str], all_signals: list[str]) -> dict:
        """Test wrapper for compatibility."""
        score = min(max(score, 0.0), 100.0)
        import json
        from pathlib import Path
        meta_path = Path("training/export/model_metadata.json")
        opt_threshold = 0.40
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                opt_threshold = float(meta.get("optimal_threshold", 0.40))
            except Exception:
                pass

        block_t = opt_threshold * 100.0
        warn_t = block_t * 0.7

        if score >= block_t:
            action = "block"
        elif score >= warn_t:
            action = "warn"
        else:
            action = "allow"
        return {
            "action": action,
            "score": score,
            "signals": signals,
            "all_signals": all_signals
        }
