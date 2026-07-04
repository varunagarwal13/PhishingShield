# PhishingShield Model Benchmarking & Stacking Comparison Report

This report compares model candidates and details why **VotingEnsemble** was selected for production.

## 1. Candidate Comparison Table (5-Fold CV)

| Model Name | Mean CV MCC | ROC-AUC | Recall | Balanced Accuracy | Brier Score | Log Loss | Training Time (s) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **LightGBM** | 0.99837 | 0.99958 | 0.99846 | 0.99918 | 0.00079 | 0.00565 | 3.43s |
| **XGBoost** | 0.99833 | 0.99958 | 0.99836 | 0.99917 | 0.00081 | 0.00562 | 4.00s |
| **RandomForest** | 0.99840 | 0.99974 | 0.99840 | 0.99920 | 0.00085 | 0.00736 | 4.36s |
| **ExtraTrees** | 0.99681 | 0.99973 | 0.99679 | 0.99840 | 0.00474 | 0.03617 | 2.58s |
| **HistGradientBoosting** | 0.99840 | 0.99955 | 0.99843 | 0.99920 | 0.00079 | 0.00594 | 2.98s |
| **VotingEnsemble** | 0.99837 | 0.99977 | 0.99836 | 0.99918 | 0.00108 | 0.01227 | 11.32s |

## 2. Threshold Search Curves Optimization

- **Selected Model**: `VotingEnsemble`
- **Optimal Decision Threshold**: `0.1000`
- **Matthews Correlation Coefficient (MCC)**: `0.98999`
- **False Positive Rate (FPR)**: `0.00%` (Strictly under 1.0% limit constraint)
