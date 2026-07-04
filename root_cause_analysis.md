# PhishingShield Root Cause Analysis

## 1. Executive Summary

Obvious phishing URLs (e.g. `paypal-security-update.com/login`) were previously returning `ALLOW` despite the calibrated LightGBM model predicting a 20%-25% risk probability.

## 2. Root Cause Identified

- **Hardcoded Decision Boundary**: The meta-scoring engine in `app/services/scoring/scoring.py` evaluated a hardcoded threshold where scores < 40 were classified as `ALLOW` and scores >= 70 as `BLOCK`.
- **Dynamic Threshold Disconnection**: The calibrated VotingEnsemble model has an optimized decision threshold of `0.1000` (maximizing MCC with 0% FPR). This requires blocking any URL with a score >= 10.0.
- **Logic Gap**: Scores of 20.0 to 25.0 are significantly above the 10.0 threshold boundary, but fell below the hardcoded 40 threshold limit in `ScoringService`, causing them to return `ALLOW` erroneously.

## 3. Resolution Applied

Modified `app/services/scoring/scoring.py` to retrieve `optimal_threshold` dynamically from `training/export/model_metadata.json` (scaling it to the 0-100 score bounds). Boundary actions now evaluate correctly.
