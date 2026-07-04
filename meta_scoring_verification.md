# PhishingShield Meta-Scoring Verification Report

This document verifies the mathematical risk aggregation flow in the scoring engine.

### Verification Checklist

- **[x] Weights Applied**: All 7 detector weights are applied dynamically.
- **[x] Dynamic Scaling**: If any detector (e.g. `visual_hash`) is skipped or returns status `no_screenshot_available`, weights are dynamically normalized to sum to 1.0.
- **[x] Threshold Boundary**: Evaluates the decision threshold from metadata (`10.0` points) instead of hardcoded numbers.
- **[x] Verdict**: Risk score >= 10.0 matches `BLOCK` correctly.
