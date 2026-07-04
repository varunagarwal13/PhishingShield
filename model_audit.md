# PhishingShield Independent Audit: AI Model Audit

This report details the verification of the AI Model artifacts, serialization, features count, calibration Wrapper, and compatibility with the inference pipeline.

---

## 1. AI Model Artifacts Verification

* **structured_model.pkl**: `VERIFIED`. The serialized RandomForest estimator was loaded using `joblib.load()`.
* **model_metadata.json**: `VERIFIED`. Holds configuration schemas, training metrics, features count, and training timestamps.
* **Model Version**: `3.0.0`
* **Model Type**: Calibrated `RandomForestClassifier`

---

## 2. Feature Schema & Count

* **Feature Schema Count**: `91` retained features after correlation and Mutual Information pruning.
* **Feature Schema Consistency**: `VERIFIED`. All features matched the exact ordering used by the offline feature extractor during model training.
* **Pipeline Alignment**: `VERIFIED`. `ModelRegistry.get_feature_schema()` loaded the exact 91-feature schema on startup, and `UrlAnalysisDetector` dynamically aligns inputs to prevent shape mismatches.

---

## 3. Probability Calibration Wrapper

* **Calibration Mechanism**: `CalibratedClassifierCV` wrapper using isotonic regression.
* **Probability Output**: Correctly outputs calibrated probability intervals, returning a valid float array `[prob_benign, prob_malicious]` during runtime prediction.
