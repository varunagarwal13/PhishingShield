"""Matplotlib plots generator for independent model validation evaluations."""

from __future__ import annotations

import logging
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, precision_recall_curve
from sklearn.calibration import calibration_curve

logger = logging.getLogger("evaluation_plots")


def plot_roc_curve(y_true: np.ndarray, y_prob: np.ndarray, output_path: str) -> None:
    try:
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color="darkorange", lw=2, label="ROC Curve")
        plt.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("Receiver Operating Characteristic (ROC)")
        plt.legend(loc="lower right")
        plt.grid(True)
        plt.savefig(output_path, dpi=300)
        plt.close()
    except Exception as e:
        logger.error(f"Failed to plot ROC: {e}")


def plot_pr_curve(y_true: np.ndarray, y_prob: np.ndarray, output_path: str) -> None:
    try:
        precision, recall, _ = precision_recall_curve(y_true, y_prob)
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, color="blue", lw=2, label="Precision-Recall Curve")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title("Precision-Recall Curve")
        plt.legend(loc="lower left")
        plt.grid(True)
        plt.savefig(output_path, dpi=300)
        plt.close()
    except Exception as e:
        logger.error(f"Failed to plot PR: {e}")


def plot_calibration_curve_chart(y_true: np.ndarray, y_prob: np.ndarray, output_path: str) -> None:
    try:
        prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=10)
        plt.figure(figsize=(8, 6))
        plt.plot(prob_pred, prob_true, marker="s", label="Calibrated Model", color="green")
        plt.plot([0, 1], [0, 1], linestyle="--", label="Perfect Calibration", color="gray")
        plt.xlabel("Mean Predicted Probability")
        plt.ylabel("Fraction of Positives")
        plt.title("Calibration Curve (Reliability Diagram)")
        plt.legend(loc="lower right")
        plt.grid(True)
        plt.savefig(output_path, dpi=300)
        plt.close()
    except Exception as e:
        logger.error(f"Failed to plot calibration: {e}")


def plot_feature_importance_chart(model, feature_names: list[str], output_path: str) -> None:
    try:
        if hasattr(model, "calibrated_classifiers_"):
            estimators = model.calibrated_classifiers_
            importances = np.mean([est.estimator.feature_importances_ for est in estimators], axis=0)
        else:
            estimators = model.estimators_
            importances = np.mean([est.feature_importances_ for est in estimators], axis=0)
            
        indices = np.argsort(importances)[::-1]
        
        plt.figure(figsize=(10, 6))
        plt.title("LightGBM Model Feature Importance (CV Mean)")
        plt.bar(range(len(feature_names)), importances[indices], align="center")
        plt.xticks(range(len(feature_names)), [feature_names[i] for i in indices], rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(output_path, dpi=300)
        plt.close()
    except Exception as e:
        logger.error(f"Failed to plot feature importance: {e}")


def plot_probability_distribution(y_prob: np.ndarray, output_path: str) -> None:
    try:
        plt.figure(figsize=(8, 6))
        plt.hist(y_prob, bins=20, edgecolor="black", color="skyblue", rwidth=0.9)
        plt.xlabel("Predicted Phishing Probability")
        plt.ylabel("Sample Count")
        plt.title("Prediction Probability Distribution Bins")
        plt.grid(True, axis="y")
        plt.savefig(output_path, dpi=300)
        plt.close()
    except Exception as e:
        logger.error(f"Failed to plot probability distribution: {e}")


def plot_confidence_histogram(y_pred: np.ndarray, y_prob: np.ndarray, output_path: str) -> None:
    try:
        conf = np.where(y_pred == 1, y_prob, 1.0 - y_prob)
        plt.figure(figsize=(8, 6))
        plt.hist(conf, bins=10, range=(0.5, 1.0), edgecolor="black", color="salmon", rwidth=0.9)
        plt.xlabel("Model Confidence Level")
        plt.ylabel("Sample Count")
        plt.title("Prediction Confidence Histogram")
        plt.grid(True, axis="y")
        plt.savefig(output_path, dpi=300)
        plt.close()
    except Exception as e:
        logger.error(f"Failed to plot confidence histogram: {e}")


def plot_confusion_matrix_chart(tn: int, fp: int, fn: int, tp: int, output_path: str) -> None:
    try:
        cm = np.array([[tn, fp], [fn, tp]])
        plt.figure(figsize=(6, 5))
        plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        plt.title("Confusion Matrix")
        plt.colorbar()
        classes = ["Benign", "Phishing"]
        tick_marks = np.arange(len(classes))
        plt.xticks(tick_marks, classes)
        plt.yticks(tick_marks, classes)
        
        thresh = cm.max() / 2.0
        for i, j in np.ndindex(cm.shape):
            plt.text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black"
            )
            
        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")
        plt.tight_layout()
        plt.savefig(output_path, dpi=300)
        plt.close()
    except Exception as e:
        logger.error(f"Failed to plot confusion matrix: {e}")
