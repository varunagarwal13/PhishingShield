# Phase 1 Verification Audit Report

This document independently audits the validation framework code, metrics, and batch scalability.

## 1. Metrics Consistency Audit

| Metric Name | Recomputed directly from Predictions | Reported in metrics.json | Diff Status |
| :--- | :--- | :--- | :--- |
| Accuracy | 0.999495 | 0.999495 | ✓ MATCH |
| Precision | 1.000000 | 1.000000 | ✓ MATCH |
| Recall | 0.998754 | 0.998754 | ✓ MATCH |
| F1 Score | 0.999377 | 0.999377 | ✓ MATCH |
| Balanced Accuracy | 0.999377 | 0.999377 | ✓ MATCH |
| ROC-AUC | 0.999858 | 0.999858 | ✓ MATCH |
| PR-AUC | 0.999860 | 0.999860 | ✓ MATCH |
| MCC | 0.998953 | 0.998953 | ✓ MATCH |
| Log Loss | 0.002985 | 0.002985 | ✓ MATCH |
| Brier Score | 0.000454 | 0.000454 | ✓ MATCH |
| FPR | 0.000000 | 0.000000 | ✓ MATCH |
| FNR | 0.001246 | 0.001246 | ✓ MATCH |
| Specificity | 1.000000 | 1.000000 | ✓ MATCH |
| Sensitivity | 0.998754 | 0.998754 | ✓ MATCH |

## 2. Confusion Matrix Audit

- **True Negatives (TN)**: `20026`
- **False Positives (FP)**: `0`
- **False Negatives (FN)**: `17`
- **True Positives (TP)**: `13627`

## 3. Scale and Batch Verification

- **Batch 128 vs 512 Predictions Match**: `True`
- **Batch 512 vs 1024 Predictions Match**: `True`
- **Deterministic Execution**: Run twice yields identical predictions.

## 4. Code and Codebase Audit findings

- **Model Retraining**: Confirmed model is loaded in read-only mode using `joblib.load()`. No fit/training steps are called.
- **Metadata Audit**: Model schema version, column mappings, and features count exactly match standard expectations.
- **Code Hardcoding**: Searched all files under `evaluation/`. Verified all calculations are dynamically computed from predictions data (no mocked results found).
