# PhishingShield Canonical Validation Summary

This document summarizes independent metrics computed directly from predictions of the production model under dynamic thresholds.

## 1. Metrics Validation Table

| Dataset | Size | Accuracy | Specificity | Sensitivity | Brier Score | FPR | FNR | MCC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Internal Test Split** | 5000 | 0.99760 | 0.99948 | 0.99155 | 0.00203 | 0.00052 | 0.00845 | 0.99335 |
| **PhishTank** | 1 | 1.00000 | 0.00000 | 1.00000 | 0.00000 | 0.00000 | 0.00000 | Not Applicable (single-class dataset) |
| **URLHaus** | 1000 | 0.99900 | 0.00000 | 0.99900 | 0.00099 | 0.00000 | 0.00100 | Not Applicable (single-class dataset) |
| **OpenPhish** | 144 | 0.27083 | 0.00000 | 0.27083 | 0.74490 | 0.00000 | 0.72917 | Not Applicable (single-class dataset) |
| **Tranco** | 1000 | 1.00000 | 1.00000 | 0.00000 | 0.00001 | 0.00000 | 0.00000 | Not Applicable (single-class dataset) |
| **Cisco Umbrella** | 1000 | 1.00000 | 1.00000 | 0.00000 | 0.00008 | 0.00000 | 0.00000 | Not Applicable (single-class dataset) |
| **urls.txt** | 5000 | 0.75400 | 0.00000 | 0.75400 | 0.25292 | 0.00000 | 0.24600 | Not Applicable (single-class dataset) |

## 2. Confusion Matrices

### Internal Test Split
- TN: `3815`
- FP: `2`
- FN: `10`
- TP: `1173`

### PhishTank
- TN: `0`
- FP: `0`
- FN: `0`
- TP: `1`

### URLHaus
- TN: `0`
- FP: `0`
- FN: `1`
- TP: `999`

### OpenPhish
- TN: `0`
- FP: `0`
- FN: `105`
- TP: `39`

### Tranco
- TN: `1000`
- FP: `0`
- FN: `0`
- TP: `0`

### Cisco Umbrella
- TN: `1000`
- FP: `0`
- FN: `0`
- TP: `0`

### urls.txt
- TN: `0`
- FP: `0`
- FN: `1230`
- TP: `3770`

