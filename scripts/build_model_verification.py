"""Programmatic verification of the production ML model."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import time
import joblib
import numpy as np

from training.feature_engineering.features import FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("model_verification")


def run_verification():
    logger.info("Initializing model verification check...")
    
    model_path = Path("training/export/structured_model.pkl")
    meta_path = Path("training/export/model_metadata.json")
    
    # 1. Verify existence
    exists = model_path.exists()
    size = model_path.stat().st_size if exists else 0
    mtime = time.ctime(model_path.stat().st_mtime) if exists else "N/A"
    
    # 2. Compute SHA256
    if exists:
        h = hashlib.sha256(open(model_path, "rb").read()).hexdigest()
    else:
        h = "N/A"
        
    # 3. Load model and inspect hierarchy
    hierarchy_str = ""
    predict_works = False
    expected_feature_count = 0
    
    if exists:
        try:
            model = joblib.load(model_path)
            hierarchy_str = str(model)
            # CalibratedClassifierCV details
            base_estimator = getattr(model, "estimator", None)
            calibrated_len = len(getattr(model, "calibrated_classifiers_", []))
            
            # Predict check
            X = np.zeros((1, 77), dtype=np.float32)
            y_prob = model.predict_proba(X)
            predict_works = y_prob.shape == (1, 2)
            expected_feature_count = 77
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            predict_works = False
            
    # 4. Load metadata
    meta_loaded = False
    meta_threshold = 0.50
    meta_features = []
    meta_timestamp = ""
    meta_type = ""
    
    if meta_path.exists():
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            meta_loaded = True
            meta_threshold = meta.get("optimal_threshold", 0.50)
            meta_features = meta.get("feature_schema", [])
            meta_timestamp = meta.get("training_timestamp", "")
            meta_type = meta.get("model_type", "")
        except Exception as e:
            logger.error(f"Error loading metadata: {e}")
            meta_loaded = False
            
    # 5. Schema verification: check for missing, extra, and ordering mismatches
    missing_features = []
    extra_features = []
    ordering_mismatch = False
    
    # Every feature expected by the model (meta_features) must exist in features.py (FEATURE_COLUMNS)
    for col in meta_features:
        if col not in FEATURE_COLUMNS:
            missing_features.append(col)
            
    # Extra features calculated in features.py but not used by model
    for col in FEATURE_COLUMNS:
        if col not in meta_features:
            extra_features.append(col)
            
    # Check ordering: if we query features.py columns sequence vs metadata sequence
    common_meta = [c for c in meta_features if c in FEATURE_COLUMNS]
    common_feat = [c for c in FEATURE_COLUMNS if c in meta_features]
    if common_meta != common_feat:
        ordering_mismatch = True
        
    passed = exists and predict_works and meta_loaded and not missing_features and not ordering_mismatch
    
    # Produce model_verification.md
    report_path = Path("model_verification.md")
    logger.info(f"Writing verification report to {report_path}...")
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# PhishingShield Canonical Model Verification Report\n\n")
        f.write("This document summarizes programmatic checks confirming serialisation structure, hierarchy compatibility, and schemas alignment.\n\n")
        
        f.write("## 1. Model Artifact Specifications\n\n")
        f.write(f"- **Structured Model Path**: `training/export/structured_model.pkl`\n")
        f.write(f"- **Existence Status**: `{'Found' if exists else 'Not Found'}`\n")
        f.write(f"- **File Size**: `{size} bytes`\n")
        f.write(f"- **SHA256 Hash**: `{h}`\n")
        f.write(f"- **Modification Timestamp**: `{mtime}`\n\n")
        
        f.write("## 2. Estimator Hierarchy Details\n\n")
        f.write("```text\n")
        f.write(hierarchy_str[:1000] + "\n")
        f.write("```\n\n")
        
        f.write("## 3. Metadata Parameters Mappings\n\n")
        f.write(f"- **Metadata Path**: `training/export/model_metadata.json`\n")
        f.write(f"- **Training Timestamp**: `{meta_timestamp}`\n")
        f.write(f"- **Model Type**: `{meta_type}`\n")
        f.write(f"- **Expectations Feature Count**: `{len(meta_features)}` features\n")
        f.write(f"- **Optimal Decision Threshold**: `{meta_threshold:.4f}`\n\n")
        
        f.write("## 4. Schemas Alignments Audit\n\n")
        f.write(f"- **Expected Feature Count**: `{expected_feature_count}`\n")
        f.write(f"- **Missing Features**: `{len(missing_features)}` {missing_features}\n")
        f.write(f"- **Extra Features**: `{len(extra_features)}` pruned features\n")
        f.write(f"- **Ordering Mismatches**: `{'Yes' if ordering_mismatch else 'None'}`\n\n")
        
        verdict = "PASS" if passed else "FAIL"
        f.write(f"## 5. Verification Verdict\n\n")
        f.write(f"**Final Verdict**: `{verdict}`\n")
        
    logger.info(f"✓ Model verification completed with verdict: {verdict}")


if __name__ == "__main__":
    run_verification()
