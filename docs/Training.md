# PhishingShield ML Model Training Pipeline

## Dataset Construction

Datasets are constructed using Tranco, Cisco Umbrella (benign), and PhishTank / URLHaus (malicious) feeds. Domain-level splits are enforced to guarantee zero data leakage between splits.

## Running Training

To train and export the production model, run:
```bash
python training/training/train.py
```

This runs grid search cross-validation, checks for accuracy and FPR boundaries, and exports:
- `training/export/structured_model.pkl`
- `training/export/model_metadata.json`
