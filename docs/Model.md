# PhishingShield Model Architecture

## Estimator Ensemble

The scoring engine implements a `CalibratedClassifierCV` wrapper around a `VotingClassifier` consisting of:
- LightGBM (Gradient Boosting)
- XGBoost
- Random Forest
- Extra Trees Classifier

Optimal decision boundary is dynamically read from `model_metadata.json` to configure final BLOCK/ALLOW thresholds.
