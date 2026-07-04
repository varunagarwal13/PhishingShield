"""Fresh verification and curves generation for all evaluation splits."""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
import time
import numpy as np
import joblib
import matplotlib.pyplot as plt
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, matthews_corrcoef,
    balanced_accuracy_score, log_loss, brier_score_loss, confusion_matrix
)

from training.feature_engineering.features import extract_url_features

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("canonical_evaluation")

PLOT_DIR = Path("evaluation/plots")
PLOT_DIR.mkdir(parents=True, exist_ok=True)


def run_evaluation():
    logger.info("Initializing fresh canonical evaluation runs...")
    
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
    eval_groups["Internal Test Split"] = random.sample(test_data, min(len(test_data), 5000))
    eval_groups["PhishTank"] = split_groups["PhishTank"]
    eval_groups["URLHaus"] = random.sample(split_groups["URLHaus"], min(len(split_groups["URLHaus"]), 1000))
    eval_groups["OpenPhish"] = split_groups["OpenPhish"]
    eval_groups["Tranco"] = random.sample(split_groups["Tranco"], min(len(split_groups["Tranco"]), 1000))
    eval_groups["Cisco Umbrella"] = random.sample(split_groups["CiscoUmbrella"], min(len(split_groups["CiscoUmbrella"]), 1000))
    
    if urls_txt_path.exists():
        urls_txt_list = []
        with open(urls_txt_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    urls_txt_list.append({"url": line, "label": 1})
        eval_groups["urls.txt"] = random.sample(urls_txt_list, min(len(urls_txt_list), 5000))
        
    metrics_report = {}
    
    # Configure matplotlib styles
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    fig_roc, ax_roc = plt.subplots(figsize=(8, 6))
    fig_pr, ax_pr = plt.subplots(figsize=(8, 6))
    fig_cal, ax_cal = plt.subplots(figsize=(8, 6))
    
    for name, data in eval_groups.items():
        logger.info(f"Evaluating dataset split: {name}...")
        urls = [item["url"] for item in data]
        y_true = np.array([int(item["label"]) for item in data])
        
        X_list = []
        for url in urls:
            feat = extract_url_features(url)
            X_list.append([feat[col] for col in schema])
        X = np.array(X_list, dtype=np.float32)
        
        y_prob = model.predict_proba(X)[:, 1]
        y_pred = (y_prob >= threshold).astype(int)
        
        # Calculate metric values
        acc = accuracy_score(y_true, y_pred)
        
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
                
                # Plot ROC / PR / Calibration curves for multi-class splits
                fpr_pts, tpr_pts, _ = precision_recall_curve(y_true, y_prob) # placeholder for ROC/PR points
                from sklearn.metrics import roc_curve
                f_p, t_p, _ = roc_curve(y_true, y_prob)
                ax_roc.plot(f_p, t_p, label=f"{name} (AUC = {auc_val:.3f})")
                ax_pr.plot(r_pts, p_pts, label=f"{name} (AUC = {pr_auc_val:.3f})")
                
                prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=10)
                ax_cal.plot(prob_pred, prob_true, marker='o', label=f"{name}")
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
        
        metrics_report[name] = {
            "size": len(data),
            "accuracy": float(acc) if not isinstance(acc, str) else acc,
            "precision": float(prec) if not isinstance(prec, str) else prec,
            "recall": float(rec) if not isinstance(rec, str) else rec,
            "f1": float(f1) if not isinstance(f1, str) else f1,
            "roc_auc": float(auc_val) if not isinstance(auc_val, str) else auc_val,
            "pr_auc": float(pr_auc_val) if not isinstance(pr_auc_val, str) else pr_auc_val,
            "balanced_accuracy": float(bal_acc) if not isinstance(bal_acc, str) else bal_acc,
            "specificity": float(specificity),
            "sensitivity": float(sensitivity),
            "mcc": float(mcc) if not isinstance(mcc, str) else mcc,
            "log_loss": float(loss) if not isinstance(loss, str) else loss,
            "brier_score": float(brier),
            "fpr": float(fpr),
            "fnr": float(fnr),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        }
        
    # Format ROC Curve plot
    ax_roc.plot([0, 1], [0, 1], linestyle='--', color='gray')
    ax_roc.set_title("ROC Curves - PhishingShield Production Model")
    ax_roc.set_xlabel("False Positive Rate")
    ax_roc.set_ylabel("True Positive Rate")
    ax_roc.legend(loc="lower right")
    fig_roc.savefig(PLOT_DIR / "roc_curve.png", dpi=150)
    plt.close(fig_roc)
    
    # Format PR Curve plot
    ax_pr.set_title("Precision-Recall Curves")
    ax_pr.set_xlabel("Recall")
    ax_pr.set_ylabel("Precision")
    ax_pr.legend(loc="lower left")
    fig_pr.savefig(PLOT_DIR / "pr_curve.png", dpi=150)
    plt.close(fig_pr)
    
    # Format Calibration plot
    ax_cal.plot([0, 1], [0, 1], linestyle='--', color='gray')
    ax_cal.set_title("Calibration Curves")
    ax_cal.set_xlabel("Mean Predicted Probability")
    ax_cal.set_ylabel("Fraction of Positives")
    ax_cal.legend(loc="upper left")
    fig_cal.savefig(PLOT_DIR / "calibration_curve.png", dpi=150)
    plt.close(fig_cal)
    
    # Save confusion matrix plot for the Internal Test Split
    fig_cm, ax_cm = plt.subplots(figsize=(6, 6))
    r = metrics_report["Internal Test Split"]
    cm_arr = np.array([[r["tn"], r["fp"]], [r["fn"], r["tp"]]])
    im = ax_cm.imshow(cm_arr, interpolation='nearest', cmap=plt.cm.Blues)
    ax_cm.set_title("Confusion Matrix - Internal Test Split")
    ax_cm.set_xticks([0, 1])
    ax_cm.set_yticks([0, 1])
    ax_cm.set_xticklabels(["Benign", "Phishing"])
    ax_cm.set_yticklabels(["Benign", "Phishing"])
    for i in range(2):
        for j in range(2):
            ax_cm.text(j, i, str(cm_arr[i, j]), ha="center", va="center", color="black")
    fig_cm.savefig(PLOT_DIR / "confusion_matrix.png", dpi=150)
    plt.close(fig_cm)
    
    # Save metrics.json
    with open("metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_report, f, indent=2)
        
    # Save metrics.csv
    with open("metrics.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Dataset", "Size", "Accuracy", "Precision", "Recall", "F1",
            "ROC-AUC", "PR-AUC", "Balanced Accuracy", "Specificity",
            "Sensitivity", "MCC", "Log Loss", "Brier Score", "FPR", "FNR"
        ])
        for name, r in metrics_report.items():
            writer.writerow([
                name, r["size"], r["accuracy"], r["precision"], r["recall"],
                r["f1"], r["roc_auc"], r["pr_auc"], r["balanced_accuracy"],
                r["specificity"], r["sensitivity"], r["mcc"], r["log_loss"],
                r["brier_score"], r["fpr"], r["fnr"]
            ])
            
    # Overwrite validation_summary.md
    with open("validation_summary.md", "w", encoding="utf-8") as f:
        f.write("# PhishingShield Canonical Validation Summary\n\n")
        f.write("This document summarizes independent metrics computed directly from predictions of the production model under dynamic thresholds.\n\n")
        
        f.write("## 1. Metrics Validation Table\n\n")
        f.write("| Dataset | Size | Accuracy | Specificity | Sensitivity | Brier Score | FPR | FNR | MCC |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for name, r in metrics_report.items():
            acc_str = r['accuracy'] if isinstance(r['accuracy'], str) else f"{r['accuracy']:.5f}"
            mcc_str = r['mcc'] if isinstance(r['mcc'], str) else f"{r['mcc']:.5f}"
            f.write(f"| **{name}** | {r['size']} | {acc_str} | {r['specificity']:.5f} | {r['sensitivity']:.5f} | {r['brier_score']:.5f} | {r['fpr']:.5f} | {r['fnr']:.5f} | {mcc_str} |\n")
            
        f.write("\n## 2. Confusion Matrices\n\n")
        for name, r in metrics_report.items():
            f.write(f"### {name}\n")
            f.write(f"- TN: `{r['tn']}`\n")
            f.write(f"- FP: `{r['fp']}`\n")
            f.write(f"- FN: `{r['fn']}`\n")
            f.write(f"- TP: `{r['tp']}`\n\n")
            
    logger.info("✓ Fresh evaluation completed successfully.")


if __name__ == "__main__":
    run_evaluation()
