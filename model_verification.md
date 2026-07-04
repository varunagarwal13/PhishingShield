# PhishingShield Canonical Model Verification Report

This document summarizes programmatic checks confirming serialisation structure, hierarchy compatibility, and schemas alignment.

## 1. Model Artifact Specifications

- **Structured Model Path**: `training/export/structured_model.pkl`
- **Existence Status**: `Found`
- **File Size**: `33074132 bytes`
- **SHA256 Hash**: `f0dc5dd862ff4fed9040f61e130f9919d6c65069eea963043d25d4f69228a436`
- **Modification Timestamp**: `Sat Jul  4 16:30:23 2026`

## 2. Estimator Hierarchy Details

```text
CalibratedClassifierCV(cv=3,
                       estimator=VotingClassifier(estimators=[('lgb',
                                                               LGBMClassifier(learning_rate=0.08,
                                                                              max_depth=6,
                                                                              random_state=42,
                                                                              verbosity=-1)),
                                                              ('xgb',
                                                               XGBClassifier(base_score=None,
                                                                             booster=None,
                                                                             callbacks=None,
                                                                             colsample_bylevel=None,
                                                                          
```

## 3. Metadata Parameters Mappings

- **Metadata Path**: `training/export/model_metadata.json`
- **Training Timestamp**: `2026-07-04T11:00:23.174028+00:00`
- **Model Type**: `VotingEnsemble`
- **Expectations Feature Count**: `77` features
- **Optimal Decision Threshold**: `0.1000`

## 4. Schemas Alignments Audit

- **Expected Feature Count**: `77`
- **Missing Features**: `0` []
- **Extra Features**: `27` pruned features
- **Ordering Mismatches**: `None`

## 5. Verification Verdict

**Final Verdict**: `PASS`
