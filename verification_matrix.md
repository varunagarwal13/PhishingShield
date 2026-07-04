# PhishingShield Forensic Verification Matrix

This matrix verifies the claims made in every audit report in this repository against the actual codebase, model parameters, and database schemas.

---

## 1. Repository Audit Verification (`repository_audit.md`)

* **Directory Structure Layout**: `✓ VERIFIED`
  * *Code Evidence*: Physical directory structure scanned and verified.
* **Imports & Circular Dependencies**: `✓ VERIFIED`
  * *Code Evidence*: Imports validated dynamically. All modules resolve without circular references.
* **Dead Code / Deprecated Modules**: `✓ VERIFIED`
  * *Code Evidence*: Deprecated script files (e.g. `evaluate_external_phishing.py`) reside in the root folder but are not imported by active server scripts.
* **TODO / Placeholders Scan**: `✓ VERIFIED`
  * *Code Evidence*: Checked files across `app/`. No placeholders or blank stubs exist in active detection pipelines.

---

## 2. Model Audit Verification (`model_audit.md`)

* **structured_model.pkl Loading**: `✓ VERIFIED`
  * *Code Evidence*: [model_loader.py:L27](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/ai/loaders/model_loader.py#L27) uses `joblib.load()` to parse the binary.
* **Feature Schema Ordering Alignment**: `✓ VERIFIED`
  * *Code Evidence*: [detector.py:L35-37](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/detectors/url_analysis/detector.py#L35-L37) pulls the schema dynamically from `ModelRegistry.get_feature_schema()` to build the inference array.
* **Probability Calibration wrapper**: `✓ VERIFIED`
  * *Code Evidence*: Scikit-Learn `CalibratedClassifierCV` wrapper is fitted and verified at [train.py:L77](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/training/training/train.py#L77).

---

## 3. Dataset Audit Verification (`dataset_audit.md`)

* **Dataset Size & Balanced Ratio**: `✓ VERIFIED`
  * *Code Evidence*: Scanned and logged inside [dataset_statistics.json](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/dataset_statistics.json) (total: 261,705 unique URLs; train split: 130,280 balanced).
* **Domain-level Split Leakage Protection**: `✓ VERIFIED`
  * *Code Evidence*: [validate.py:L130-148](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/training/validation/validate.py#L130-L148) splits on registered domains and verifies that `train_domains.intersection(test_domains)` is empty.
* **Licensing Provenance**: `✓ VERIFIED`
  * *Code Evidence*: Logged inside [dataset_statistics.json:L26-32](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/dataset_statistics.json#L26-L32) mapping appropriate licenses for each feed.

---

## 4. Feature Engineering Audit Verification (`feature_audit.md`)

* **101 Features space**: `✓ VERIFIED`
  * *Code Evidence*: Fully implemented inside [features.py:L130-221](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/training/feature_engineering/features.py#L130-L221) (extracts structural ratios, character analysis, and brand similarity matrices).
* **Automated Selection**: `✓ VERIFIED`
  * *Code Evidence*: Implemented inside [feature_selection.py:L38-66](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/training/training/feature_selection.py#L38-L66) (filters features using Pearson correlation thresholds and Mutual Information scores).

---

## 5. Detector Audit Verification (`detector_audit.md`)

* **7 Active Modules**: `✓ VERIFIED`
  * *Code Evidence*: Instantiated and mapped inside [pipeline.py:L51-59](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/pipeline/pipeline.py#L51-L59).
* **Exception Isolation Safety**: `✓ VERIFIED`
  * *Code Evidence*: Implemented in base wrapper [base_detector.py:L34-52](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/detectors/base_detector.py#L34-L52) intercepting children errors and returning `failed=True`.
* **Inference Timeouts**: `✓ VERIFIED`
  * *Code Evidence*: [detector.py:L34-35](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/detectors/threat_intelligence/detector.py#L34-L35) sets `aiohttp.ClientTimeout(total=4)` (4 seconds limit).
* **Fallback Handler**: `✓ VERIFIED`
  * *Code Evidence*: [detector.py:L49-65](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/detectors/url_analysis/detector.py#L49-L65) executes heuristic rule fallbacks if model is unset.

---

## 6. Pipeline Audit Verification (`pipeline_audit.md`)

* **asyncio.gather Parallelism**: `✓ VERIFIED`
  * *Code Evidence*: [pipeline.py:L147-150](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/pipeline/pipeline.py#L147-L150) runs Stage 1 detectors in parallel.
* **Early Exit Event**: `✓ VERIFIED`
  * *Code Evidence*: [pipeline.py:L170](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/pipeline/pipeline.py#L170) checks `stop_event.is_set()` before executing Stage 2 (Image analysis).
* **Persistence & Redis cache**: `✓ VERIFIED`
  * *Code Evidence*: Redis check at [pipeline.py:L66](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/pipeline/pipeline.py#L66); SQLite log at [pipeline.py:L230](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/pipeline/pipeline.py#L230).

---

## 7. Explainability Audit Verification (`xai_audit.md`)

* **Priority Tracing IDs**: `✓ VERIFIED`
  * *Code Evidence*: Evidence-mapping keywords configured inside [explanation_engine.py:L20-77](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/ai/explainability/explanation_engine.py#L20-L77).
* **MITRE ATT&CK Mapping**: `✓ VERIFIED`
  * *Code Evidence*: Technique mapping links configured inside [mitre_mapping.py:L6-36](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/ai/explainability/mitre_mapping.py#L6-L36) returning `T1566`, `T1027`, `T1622`, or `T1592`.
* **Remediation Recommendations Blocks**: `✓ VERIFIED`
  * *Code Evidence*: Structured blocks maps configured inside [recommendations.py:L8-31](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/ai/explainability/recommendations.py#L8-L31).

---

## 8. API Audit Verification (`api_audit.md`)

* **Registered Path routes**: `✓ VERIFIED`
  * *Code Evidence*: Mapped inside [routes.py](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/api/routes.py) (POST `/analyse`, POST `/feedback`, GET `/analysis/explanation`, GET `/analysis/report`, GET `/analysis/evidence`, GET `/health`).
* **Input character thresholds**: `✓ VERIFIED`
  * *Code Evidence*: [routes.py:L21-33](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/api/routes.py#L21-L33) checks URL length and scheme structures.

---

## 9. Performance Audit Verification (`performance_audit.md`)

* **Startup & Inference latency metrics**: `✓ VERIFIED`
  * *Measurement Location*: Measured by profiling execution loops on the local system and written to [performance_report.md](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/performance_report.md).
  * *Metrics Cites*: Cold Start = `2060.93ms`; Inference latency = `1.56ms/URL`; Throughput = `638.42 URLs/sec`.

---

## 10. Security Audit Verification (`security_audit.md`)

* **SSRF loopback/private host filtering**: `✓ VERIFIED`
  * *Code Evidence*: [url_utils.py:L141-165](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/utils/url_utils.py#L141-L165) checks for literal private IPs and resolves hostnames via DNS resolver queries before checks.
* **Homograph skeleton translation**: `✓ VERIFIED`
  * *Code Evidence*: [url_utils.py:L121-128](file:///c:/Users/varun/OneDrive/Desktop/PS/PhishingShield/app/utils/url_utils.py#L121-L128) translates string skeletons against homoglyph maps to identify target spoofings.

---

## 11. Final Verification Report (`final_verification_report.md`)

* **Recomputed Metrics**: `✓ VERIFIED`
  * *Measurement Location*: Calculated programmatically over test split JSON pools via the audit verification tool.
  * *Metrics Cites*: Accuracy = `99.88%`, Precision = `100.0%`, F1 = `99.75%`, MCC = `0.9967`, Brier = `0.00137`.
* **External Datasets rate**: `✓ VERIFIED`
  * *Measurement Location*: Scanned over local copies of `urls.txt` and `openphish.txt` (100% detection rate confirmed).
