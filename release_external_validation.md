# PhishingShield Release External Validation Audit

Evaluation results under clean (non-leaked) stacking VotingEnsemble:

| Dataset | Accuracy | Specificity | Sensitivity | Brier Score | FPR |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Internal Test Split** | 0.99760 | 0.99948 | 0.99155 | 0.00203 | 0.052% |
| **URLHaus (Unseen)** | 0.99900 | 0.00000 | 0.99900 | 0.00099 | 0.000% |
| **urls.txt (External)** | 0.75400 | 0.00000 | 0.75400 | 0.25292 | 0.000% |
| **OpenPhish (Unseen)** | 0.27083 | 0.00000 | 0.27083 | 0.74490 | 0.000% |
