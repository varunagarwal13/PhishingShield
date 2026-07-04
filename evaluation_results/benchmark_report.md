# PhishingShield Model Validation & Evaluation Report

This report validates the PhishingShield ML model against an unseen dataset benchmark.

## 1. Dataset Parameters

- **Format Detected**: `json`
- **Total Rows Read**: `33670`
- **Valid URLs Scanned**: `33670`
- **Duplicates Omitted**: `0`
- **Malformed URLs Omitted**: `0`
- **Labels Present**: `True`

## 2. Model Parameters

- **Model Version**: `2.0.0`
- **Calibration**: `CalibratedClassifierCV (isotonic regression)`
- **Feature count**: `16`

## 3. Classification Performance Metrics

| Performance Metric | Value | Interpretation |
| :--- | :--- | :--- |
| **Accuracy** | 0.999495 | Percentage of correct classifications |
| **Balanced Accuracy** | 0.999377 | Accuracy adjusted for class imbalance |
| **Precision** | 1.000000 | Proportion of flagged pages that are actually phishing |
| **Recall (Sensitivity)** | 0.998754 | Proportion of actual phishing pages successfully caught |
| **Specificity** | 1.000000 | Proportion of safe pages correctly allowed |
| **F1 Score** | 0.999377 | Harmonic mean of Precision and Recall |
| **ROC-AUC** | 0.999858 | Area under the ROC curve |
| **PR-AUC** | 0.999860 | Area under the Precision-Recall curve |
| **Matthews Correlation Coefficient (MCC)** | 0.998953 | Balanced correlation quality metric (-1 to +1) |
| **Log Loss** | 0.002985 | Cross-entropy prediction loss |
| **Brier Score** | 0.000454 | Mean squared error of probabilities |
| **False Positive Rate (FPR)** | 0.000000 | Proportion of benign pages falsely blocked |
| **False Negative Rate (FNR)** | 0.001246 | Proportion of phishing pages missed |

### Graphical Performance Outputs:
- **ROC Curve**: Saved to `roc_curve.png`
- **Precision-Recall Curve**: Saved to `pr_curve.png`
- **Calibration Curve**: Saved to `calibration_curve.png`
- **Confusion Matrix**: Saved to `confusion_matrix.png`

- **Feature Importance Chart**: Saved to `feature_importance.png`
