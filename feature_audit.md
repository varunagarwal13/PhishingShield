# PhishingShield Independent Audit: Feature Engineering Audit

This report details the audit of the PhishingShield feature engineering pipeline, feature schemas, extraction logic, and online inference consistency.

---

## 1. Feature Engineering Categories

The pipeline extracts exactly 101 raw features across four domains:
1. **URL Structure (22 features)**: Measures depths, lengths, query parameters counts, and parameter entropy.
2. **Character Ratios (24 features)**: Analyzes uppercase, lowercase, consonant, vowel, and hex character densities.
3. **Brand Similarity Matrix (60 features)**: Computes Levenshtein, Jaro-Winkler, and QWERTY keyboard distance mappings against 20 key target brands.
4. **General Flags**: Unicode characters, mixed-script indicators, and risky TLD matching.

---

## 2. Selection & Pruning Metrics

* **Initial Features Space**: `101` features
* **Retained Features**: `91` features after automated correlation (Pearson $> 0.95$) and Mutual Information (MI $> 0.001$) pruning.
* **Pruned Features**: `10` redundant or zero-variance columns were successfully discarded.

---

## 3. Training vs Inference Consistency

* **Schema Preservation**: `VERIFIED`. The list of 91 selected features is compiled into the `feature_schema` property of `model_metadata.json`.
* **Alignment Logic**: `VERIFIED`. `UrlAnalysisDetector` loads the schema list from metadata dynamically and builds inputs. This guarantees `100%` input dimensions alignment between training and production runs.
