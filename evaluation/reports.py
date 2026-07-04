"""Reports compiler converting validation metrics to JSON, CSV, and Markdown logs."""

from __future__ import annotations

import csv
import json
from pathlib import Path


def write_metrics_json(metrics: dict, output_path: Path | str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


def write_metrics_csv(metrics: dict, output_path: Path | str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        for k, v in metrics.items():
            writer.writerow([k, f"{v:.6f}"])


def write_markdown_report(
    metrics: dict | None,
    dataset_stats: dict,
    model_meta: dict,
    output_path: Path | str
) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# PhishingShield Model Validation & Evaluation Report\n\n")
        f.write("This report validates the PhishingShield ML model against an unseen dataset benchmark.\n\n")

        f.write("## 1. Dataset Parameters\n\n")
        f.write(f"- **Format Detected**: `{dataset_stats.get('format')}`\n")
        f.write(f"- **Total Rows Read**: `{dataset_stats.get('total_lines_read')}`\n")
        f.write(f"- **Valid URLs Scanned**: `{dataset_stats.get('total_urls')}`\n")
        f.write(f"- **Duplicates Omitted**: `{dataset_stats.get('duplicates')}`\n")
        f.write(f"- **Malformed URLs Omitted**: `{dataset_stats.get('malformed')}`\n")
        f.write(f"- **Labels Present**: `{dataset_stats.get('labels_present')}`\n\n")

        f.write("## 2. Model Parameters\n\n")
        f.write(f"- **Model Version**: `{model_meta.get('model_version', '2.0.0')}`\n")
        f.write(f"- **Calibration**: `CalibratedClassifierCV (isotonic regression)`\n")
        f.write(f"- **Feature count**: `{len(model_meta.get('feature_schema', []))}`\n\n")

        if metrics:
            f.write("## 3. Classification Performance Metrics\n\n")
            f.write("| Performance Metric | Value | Interpretation |\n")
            f.write("| :--- | :--- | :--- |\n")
            f.write(f"| **Accuracy** | {metrics['accuracy']:.6f} | Percentage of correct classifications |\n")
            f.write(f"| **Balanced Accuracy** | {metrics['balanced_accuracy']:.6f} | Accuracy adjusted for class imbalance |\n")
            f.write(f"| **Precision** | {metrics['precision']:.6f} | Proportion of flagged pages that are actually phishing |\n")
            f.write(f"| **Recall (Sensitivity)** | {metrics['recall']:.6f} | Proportion of actual phishing pages successfully caught |\n")
            f.write(f"| **Specificity** | {metrics['specificity']:.6f} | Proportion of safe pages correctly allowed |\n")
            f.write(f"| **F1 Score** | {metrics['f1_score']:.6f} | Harmonic mean of Precision and Recall |\n")
            f.write(f"| **ROC-AUC** | {metrics['roc_auc']:.6f} | Area under the ROC curve |\n")
            f.write(f"| **PR-AUC** | {metrics['pr_auc']:.6f} | Area under the Precision-Recall curve |\n")
            f.write(f"| **Matthews Correlation Coefficient (MCC)** | {metrics['mcc']:.6f} | Balanced correlation quality metric (-1 to +1) |\n")
            f.write(f"| **Log Loss** | {metrics['log_loss']:.6f} | Cross-entropy prediction loss |\n")
            f.write(f"| **Brier Score** | {metrics['brier_score']:.6f} | Mean squared error of probabilities |\n")
            f.write(f"| **False Positive Rate (FPR)** | {metrics['fpr']:.6f} | Proportion of benign pages falsely blocked |\n")
            f.write(f"| **False Negative Rate (FNR)** | {metrics['fnr']:.6f} | Proportion of phishing pages missed |\n\n")

            # Simple text visualization
            f.write("### Graphical Performance Outputs:\n")
            f.write("- **ROC Curve**: Saved to `roc_curve.png`\n")
            f.write("- **Precision-Recall Curve**: Saved to `pr_curve.png`\n")
            f.write("- **Calibration Curve**: Saved to `calibration_curve.png`\n")
            f.write("- **Confusion Matrix**: Saved to `confusion_matrix.png`\n")
        else:
            f.write("## 3. Inference-Only Statistics (Unlabeled Dataset)\n\n")
            f.write("Because labels were absent in the input dataset, classification performance metrics could not be computed.\n")
            f.write("Inference probability histograms are available under `predictions.csv` and graphical curves.\n")

        f.write("\n- **Feature Importance Chart**: Saved to `feature_importance.png`\n")
