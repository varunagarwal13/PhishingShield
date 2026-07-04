# PhishingShield Scoring Verification Report

## 1. Threshold Configuration Audit

- **Metadata Path**: `training/export/model_metadata.json`
- **Dynamic Threshold Loaded**: `0.1`
- **Calibrated Block Boundary**: `10.0` points
- **Calibrated Warn Boundary**: `7.0` points

## 2. Hardcoded Check Code Review

- Audited `app/services/scoring/scoring.py` and confirmed no references to the legacy thresholds (40 and 70) remain in place. All actions derive directly from metadata bounds.
