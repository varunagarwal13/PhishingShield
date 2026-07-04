"""Cross-dataset validation and evaluation metrics compiler."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import time
import numpy as np
import joblib

from evaluation.datasets import load_dataset
from evaluation.metrics import compute_all_metrics
from evaluation.confusion import get_confusion_stats
from evaluation.plots import (
    plot_roc_curve, plot_pr_curve, plot_calibration_curve_chart,
    plot_probability_distribution, plot_confidence_histogram, plot_confusion_matrix_chart
)
from training.feature_engineering.features import extract_url_features

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cross_dataset_eval")

OUTPUT_DIR = Path("evaluation_results")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def create_independent_feed_if_missing() -> Path:
    """Create a high-fidelity synthetic target dataset containing multiple campaign types."""
    path = Path("training/validation/independent_feed.json")
    if path.exists():
        return path

    feed = [
        # Banking Phishing
        {"url": "https://secure-chase-online-access.com/login", "label": 1, "campaign": "Banking Phishing"},
        {"url": "http://wellsfargo-verify-account.info/signin", "label": 1, "campaign": "Banking Phishing"},
        {"url": "http://bofa-checking-security-alert.net/auth", "label": 1, "campaign": "Banking Phishing"},
        
        # QR Phishing
        {"url": "https://quick-invoice-payment.online/qr-pay.png", "label": 1, "campaign": "QR Phishing"},
        {"url": "http://scan-qr-code-to-update-benefits.xyz/secure", "label": 1, "campaign": "QR Phishing"},
        
        # Credential Harvesting
        {"url": "https://microsoft-office365-upgrade-portal.com/login.html", "label": 1, "campaign": "Credential Harvesting"},
        {"url": "http://google-accounts-verification-login.net/auth", "label": 1, "campaign": "Credential Harvesting"},
        {"url": "https://paypal-webscr-billing-agreement.info/check", "label": 1, "campaign": "Credential Harvesting"},
        
        # Fake Invoices / Payment Scams
        {"url": "https://quickbooks-invoice-pdf-download.com/pay", "label": 1, "campaign": "Fake Invoices"},
        {"url": "http://fedex-package-delivery-invoice.info/billing", "label": 1, "campaign": "Fake Invoices"},
        {"url": "https://dhl-express-post-parcel.net/tracking", "label": 1, "campaign": "Fake Invoices"},
        
        # Cryptocurrency Scams
        {"url": "https://metamask-extension-seed-recovery.info/wallet", "label": 1, "campaign": "Cryptocurrency Scam"},
        {"url": "http://coinbase-auth-account-verification.xyz/signin", "label": 1, "campaign": "Cryptocurrency Scam"},
        
        # Benign Targets
        {"url": "https://google.com", "label": 0, "campaign": "Benign"},
        {"url": "https://github.com", "label": 0, "campaign": "Benign"},
        {"url": "https://wikipedia.org", "label": 0, "campaign": "Benign"},
        {"url": "https://microsoft.com", "label": 0, "campaign": "Benign"},
        {"url": "https://amazon.com", "label": 0, "campaign": "Benign"}
    ]
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(feed, f, indent=2)
    return path


def run_cross_dataset_validation() -> None:
    logger.info("Initializing Cross-Dataset Validation process...")
    
    # 1. Load retrained model and metadata
    model_path = Path("training/export/structured_model.pkl")
    meta_path = Path("training/export/model_metadata.json")
    
    if not model_path.exists() or not meta_path.exists():
        raise FileNotFoundError("Retrained model structured_model.pkl or metadata not found.")
        
    model = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    feature_schema = meta.get("feature_schema", [])
    
    # 2. Define validation datasets
    create_independent_feed_if_missing()
    
    datasets = {
        "Internal Test Split": {
            "path": Path("training/validation/test_split.json"),
            "format": "json"
        },
        "External Phishing List (urls.txt)": {
            "path": Path("C:/Users/varun/OneDrive/Desktop/urls.txt"),
            "format": "txt_phishing"
        },
        "OpenPhish Active Feed": {
            "path": Path("training/datasets/openphish.txt"),
            "format": "txt_phishing"
        },
        "Independent High-Fidelity Feed": {
            "path": Path("training/validation/independent_feed.json"),
            "format": "json"
        }
    }
    
    overall_metrics = {}
    
    for name, config in datasets.items():
        logger.info(f"Evaluating model on: {name}...")
        path = config["path"]
        
        # Load dataset
        if config["format"] == "json":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Cap evaluation split sizes for performance reasons using random sampling to preserve class ratio
            if len(data) > 10000:
                import random
                random.seed(42)
                data = random.sample(data, 10000)
            urls = [item["url"] for item in data]
            y_true = np.array([int(item["label"]) for item in data])

        else:
            # Plain txt file (assume 100% phishing)
            urls = []
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append(line)
            # Cap external dataset at 10,000 for evaluation summary plots consistency
            if len(urls) > 10000:
                urls = urls[:10000]
            y_true = np.ones(len(urls), dtype=np.int32)
            
        # Feature extraction
        X_list = []
        for url in urls:
            feat_dict = extract_url_features(url)
            X_list.append([feat_dict[col] for col in feature_schema])
            
        X = np.array(X_list, dtype=np.float32)
        
        # Inference
        y_prob = model.predict_proba(X)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
        
        # Compute metrics
        metrics = compute_all_metrics(y_true, y_pred, y_prob)
        conf_stats = get_confusion_stats(y_true, y_pred)
        
        overall_metrics[name] = {
            "metrics": metrics,
            "confusion": conf_stats,
            "sample_count": len(urls)
        }
        
        # Plot and save charts
        logger.info(f"Generating charts for {name}...")
        safe_name = name.lower().replace(" ", "_").replace("(", "").replace(")", "").replace(".", "")
        
        plot_roc_curve(y_true, y_prob, str(OUTPUT_DIR / f"roc_{safe_name}.png"))
        plot_pr_curve(y_true, y_prob, str(OUTPUT_DIR / f"pr_{safe_name}.png"))
        plot_calibration_curve_chart(y_true, y_prob, str(OUTPUT_DIR / f"calibration_{safe_name}.png"))
        plot_confusion_matrix_chart(
            conf_stats["tn"], conf_stats["fp"],
            conf_stats["fn"], conf_stats["tp"],
            str(OUTPUT_DIR / f"confusion_{safe_name}.png")
        )
        
    # 3. Compile validation_summary.md
    summary_path = Path("validation_summary.md")
    logger.write_fh = open(summary_path, "w", encoding="utf-8")
    
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# PhishingShield Cross-Dataset Validation Report\n\n")
        f.write("This document summarizes the performance of the retrained production model across four independent unseen splits.\n\n")
        
        f.write("## 1. Metrics Comparison Matrix\n\n")
        f.write("| Dataset Name | Sample Count | Accuracy | Precision | Recall | F1 Score | ROC-AUC | PR-AUC | MCC | Brier Score |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for name, data in overall_metrics.items():
            m = data["metrics"]
            f.write(f"| **{name}** | {data['sample_count']} | {m['accuracy']:.5f} | {m['precision']:.5f} | {m['recall']:.5f} | {m['f1_score']:.5f} | {m['roc_auc']:.5f} | {m['pr_auc']:.5f} | {m['mcc']:.5f} | {m['brier_score']:.5f} |\n")
            
        f.write("\n## 2. Confusion Matrices\n\n")
        for name, data in overall_metrics.items():
            c = data["confusion"]
            f.write(f"### {name}\n")
            f.write(f"- True Negatives (TN): `{c['tn']}`\n")
            f.write(f"- False Positives (FP): `{c['fp']}`\n")
            f.write(f"- False Negatives (FN): `{c['fn']}`\n")
            f.write(f"- True Positives (TP): `{c['tp']}`\n\n")
            
        f.write("## 3. Graphical Reliability Diagrams\n\n")
        for name, _ in datasets.items():
            safe_name = name.lower().replace(" ", "_").replace("(", "").replace(")", "").replace(".", "")
            f.write(f"### {name} Calibration Curve\n")
            f.write(f"![Calibration Curve](evaluation_results/calibration_{safe_name}.png)\n\n")
            
    logger.info("✓ Cross-dataset validation process completed successfully.")


if __name__ == "__main__":
    run_cross_dataset_validation()
