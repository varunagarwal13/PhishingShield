"""Independent model validation benchmark orchestrator."""

from __future__ import annotations

import argparse
import csv
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
    plot_feature_importance_chart, plot_probability_distribution,
    plot_confidence_histogram, plot_confusion_matrix_chart
)
from evaluation.reports import write_metrics_json, write_metrics_csv, write_markdown_report
from training.feature_engineering.features import extract_url_features, FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluation_benchmark")


def main() -> None:
    parser = argparse.ArgumentParser(description="PhishingShield Independent Model Evaluator")
    parser.add_argument(
        "--dataset",
        type=str,
        default="C:\\Users\\varun\\OneDrive\\Desktop\\urls.txt",
        help="Path to external evaluation dataset"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=5000,
        help="Batch size for feature extraction and inference"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="evaluation_results",
        help="Directory to save metric charts and reports"
    )
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Loading external dataset from: {args.dataset}")
    urls, labels, dataset_stats = load_dataset(args.dataset)
    logger.info(f"Auto-detected dataset format: {dataset_stats['format']}. Loaded {dataset_stats['total_urls']} unique URLs.")
    
    # 1. Locate and Load Exported Model & Metadata
    model_path = Path("training/export/structured_model.pkl")
    meta_path = Path("training/export/model_metadata.json")
    
    if not model_path.exists():
        raise FileNotFoundError(f"Exported model not found at {model_path}. Run training pipeline first.")
        
    logger.info(f"Loading LightGBM model from {model_path}...")
    model = joblib.load(model_path)
    
    model_meta = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            model_meta = json.load(f)
        logger.info(f"Loaded model version: {model_meta.get('model_version', '2.0.0')}")
        
        # Verify schema compatibility
        meta_features = model_meta.get("feature_schema", [])
        if meta_features and meta_features != FEATURE_COLUMNS:
            logger.warning("Feature schema mismatch detected between metadata and FEATURE_COLUMNS!")
            
    # 2. Batch Feature Extraction & Inference
    total_urls = len(urls)
    all_predictions = []
    all_probabilities = []
    
    logger.info(f"Starting batch feature extraction and inference (batch_size={args.batch_size})...")
    start_time = time.time()
    
    for i in range(0, total_urls, args.batch_size):
        batch_urls = urls[i:i + args.batch_size]
        
        # Extract features
        batch_features = []
        for url in batch_urls:
            feat_dict = extract_url_features(url)
            row = [feat_dict[col] for col in FEATURE_COLUMNS]
            batch_features.append(row)
            
        X_batch = np.array(batch_features)
        
        # Predict probabilities (phishing class is index 1)
        # Handle cases where model does or does not output probability array
        try:
            probs = model.predict_proba(X_batch)[:, 1]
        except Exception:
            # Fallback for models without predict_proba (like standard regression)
            probs = model.predict(X_batch)
            
        preds = (probs >= 0.5).astype(int)
        
        all_predictions.extend(preds.tolist())
        all_probabilities.extend(probs.tolist())
        
        logger.info(f"  Processed {min(i + args.batch_size, total_urls)}/{total_urls} URLs...")
        
    elapsed = time.time() - start_time
    logger.info(f"Batch inference complete. Processed {total_urls} URLs in {elapsed:.2f}s ({total_urls/elapsed:.2f} URLs/sec).")
    
    y_pred = np.array(all_predictions)
    y_prob = np.array(all_probabilities)
    
    # 3. Save Predictions list CSV
    pred_path = output_dir / "predictions.csv"
    logger.info(f"Saving predictions to {pred_path}...")
    with open(pred_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "phishing_probability", "predicted_class"])
        for idx, url in enumerate(urls):
            writer.writerow([url, f"{all_probabilities[idx]:.6f}", all_predictions[idx]])
            
    # 4. Generate Distributions plots (always possible, even without labels)
    logger.info("Generating probability distribution and confidence histogram charts...")
    plot_probability_distribution(y_prob, str(output_dir / "probability_distribution.png"))
    plot_confidence_histogram(y_pred, y_prob, str(output_dir / "confidence_histogram.png"))
    plot_feature_importance_chart(model, FEATURE_COLUMNS, str(output_dir / "feature_importance.png"))
    
    metrics = None
    
    # 5. Calculate metrics if labels are present
    if dataset_stats["labels_present"] and labels is not None:
        logger.info("Ground-truth labels present. Computing performance metrics...")
        y_true = np.array(labels[:len(y_pred)])
        
        # Compute metrics
        metrics = compute_all_metrics(y_true, y_pred, y_prob)
        conf_stats = get_confusion_stats(y_true, y_pred)
        
        # Save JSON/CSV metrics logs
        write_metrics_json(metrics, output_dir / "metrics.json")
        write_metrics_csv(metrics, output_dir / "metrics.csv")
        
        # Plot curves
        logger.info("Plotting ROC, Precision-Recall, Calibration, and Confusion Matrix charts...")
        plot_roc_curve(y_true, y_prob, str(output_dir / "roc_curve.png"))
        plot_pr_curve(y_true, y_prob, str(output_dir / "pr_curve.png"))
        plot_calibration_curve_chart(y_true, y_prob, str(output_dir / "calibration_curve.png"))
        plot_confusion_matrix_chart(
            conf_stats["tn"], conf_stats["fp"],
            conf_stats["fn"], conf_stats["tp"],
            str(output_dir / "confusion_matrix.png")
        )
        
    # 6. Generate final markdown report
    report_path = output_dir / "benchmark_report.md"
    logger.info(f"Compiling final benchmark report to {report_path}...")
    write_markdown_report(metrics, dataset_stats, model_meta, report_path)
    
    logger.info("Independent Validation Process completed successfully!")


if __name__ == "__main__":
    main()
