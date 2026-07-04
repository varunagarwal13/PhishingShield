"""Autorun and construct canonical metrics across all evaluation splits using the dynamic threshold."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import time
import numpy as np
import joblib

from training.feature_engineering.features import extract_url_features
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, matthews_corrcoef,
    balanced_accuracy_score, log_loss, brier_score_loss, confusion_matrix
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("canonical_metrics")


def run_metrics():
    logger.info("Starting canonical metrics computations...")
    
    model_path = Path("training/export/structured_model.pkl")
    meta_path = Path("training/export/model_metadata.json")
    test_path = Path("training/validation/test_split.json")
    urls_txt_path = Path("C:/Users/varun/OneDrive/Desktop/urls.txt")
    
    model = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    schema = meta.get("feature_schema", [])
    threshold = meta.get("optimal_threshold", 0.50)
    
    with open(test_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)
        
    # Group test splits
    split_groups = {
        "PhishTank": [],
        "URLHaus": [],
        "OpenPhish": [],
        "Tranco": [],
        "CiscoUmbrella": []
    }
    
    for item in test_data:
        src = item["source"]
        for g_name in split_groups:
            if g_name in src:
                split_groups[g_name].append(item)
                
    import random
    random.seed(42)
    
    eval_groups = {}
    
    # Internal test split (balanced mix of all test_split)
    eval_groups["Internal Test Split"] = random.sample(test_data, min(len(test_data), 5000))
    
    # Unseen sources
    eval_groups["PhishTank (Unseen domains)"] = split_groups["PhishTank"]
    eval_groups["URLHaus (Unseen domains)"] = random.sample(split_groups["URLHaus"], min(len(split_groups["URLHaus"]), 1000))
    eval_groups["OpenPhish (Unseen domains)"] = split_groups["OpenPhish"]
    eval_groups["Tranco Benign (Unseen domains)"] = random.sample(split_groups["Tranco"], min(len(split_groups["Tranco"]), 1000))
    eval_groups["Cisco Umbrella (Unseen domains)"] = random.sample(split_groups["CiscoUmbrella"], min(len(split_groups["CiscoUmbrella"]), 1000))
    
    # urls.txt
    if urls_txt_path.exists():
        urls_txt_list = []
        with open(urls_txt_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    urls_txt_list.append({"url": line, "label": 1})
        eval_groups["urls.txt (External benchmark)"] = random.sample(urls_txt_list, min(len(urls_txt_list), 5000))
        
    canonical_results = {}
    
    for name, data in eval_groups.items():
        logger.info(f"Computing canonical metrics for: {name} (size: {len(data)})")
        urls = [item["url"] for item in data]
        y_true = np.array([int(item["label"]) for item in data])
        
        X_list = []
        for url in urls:
            feat = extract_url_features(url)
            X_list.append([feat[col] for col in schema])
        X = np.array(X_list, dtype=np.float32)
        
        y_prob = model.predict_proba(X)[:, 1]
        y_pred = (y_prob >= threshold).astype(int)
        
        # Calculate scores
        acc = accuracy_score(y_true, y_pred)
        
        # Safe scoring for single-class datasets
        unique_classes = np.unique(y_true)
        if len(unique_classes) > 1:
            prec = precision_score(y_true, y_pred, zero_division=0)
            rec = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            mcc = matthews_corrcoef(y_true, y_pred)
            bal_acc = balanced_accuracy_score(y_true, y_pred)
            loss = log_loss(y_true, y_prob, labels=[0, 1])
            try:
                auc_val = roc_auc_score(y_true, y_prob)
                p_pts, r_pts, _ = precision_recall_curve(y_true, y_prob)
                pr_auc_val = auc(r_pts, p_pts)
            except Exception:
                auc_val = 0.5
                pr_auc_val = 0.5
        else:
            prec = "Not Applicable (single-class dataset)"
            rec = "Not Applicable (single-class dataset)"
            f1 = "Not Applicable (single-class dataset)"
            mcc = "Not Applicable (single-class dataset)"
            bal_acc = "Not Applicable (single-class dataset)"
            loss = "Not Applicable (single-class dataset)"
            auc_val = "Not Applicable (single-class dataset)"
            pr_auc_val = "Not Applicable (single-class dataset)"
            
        brier = brier_score_loss(y_true, y_prob)
        
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
        
        canonical_results[name] = {
            "size": len(data),
            "accuracy": acc if isinstance(acc, str) else float(acc),
            "precision": prec if isinstance(prec, str) else float(prec),
            "recall": rec if isinstance(rec, str) else float(rec),
            "f1_score": f1 if isinstance(f1, str) else float(f1),
            "specificity": float(specificity),
            "sensitivity": float(sensitivity),
            "balanced_accuracy": bal_acc if isinstance(bal_acc, str) else float(bal_acc),
            "roc_auc": auc_val if isinstance(auc_val, str) else float(auc_val),
            "pr_auc": pr_auc_val if isinstance(pr_auc_val, str) else float(pr_auc_val),
            "mcc": mcc if isinstance(mcc, str) else float(mcc),
            "brier_score": float(brier),
            "log_loss": loss if isinstance(loss, str) else float(loss),
            "fpr": float(fpr),
            "fnr": float(fnr),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        }
        
    # Latencies percentiles
    logger.info("Computing latency percentiles...")
    X_lat = []
    for item in eval_groups["Internal Test Split"][:2000]:
        feat = extract_url_features(item["url"])
        X_lat.append([feat[col] for col in schema])
    X_lat = np.array(X_lat, dtype=np.float32)
    
    latencies = []
    for i in range(10):
        t_start = time.perf_counter()
        _ = model.predict_proba(X_lat)
        t_dur = (time.perf_counter() - t_start) * 1000.0 / len(X_lat)
        latencies.append(t_dur)
        
    p50_lat = np.percentile(latencies, 50)
    p95_lat = np.percentile(latencies, 95)
    p99_lat = np.percentile(latencies, 99)
    
    canonical_results["latency"] = {
        "p50_ms": float(p50_lat),
        "p95_ms": float(p95_lat),
        "p99_ms": float(p99_lat),
        "avg_ms": float(np.mean(latencies))
    }
    
    # Save output JSON
    output_path = Path("canonical_metrics.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(canonical_results, f, indent=2)
    logger.info(f"✓ Canonical metrics written to {output_path}")


if __name__ == "__main__":
    run_metrics()
