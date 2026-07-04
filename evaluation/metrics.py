"""Performance metrics calculations for model validation evaluation."""

from __future__ import annotations

import logging
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc, matthews_corrcoef,
    balanced_accuracy_score, log_loss, brier_score_loss, confusion_matrix
)

logger = logging.getLogger("evaluation_metrics")


def compute_all_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> dict[str, float]:
    """Calculate and return all advanced validation metrics as flat dictionary."""
    metrics = {}

    # Standard metrics
    metrics["accuracy"] = float(accuracy_score(y_true, y_pred))
    metrics["precision"] = float(precision_score(y_true, y_pred, zero_division=0))
    metrics["recall"] = float(recall_score(y_true, y_pred, zero_division=0))
    metrics["f1_score"] = float(f1_score(y_true, y_pred, zero_division=0))
    metrics["balanced_accuracy"] = float(balanced_accuracy_score(y_true, y_pred))
    
    # Advanced stats
    metrics["mcc"] = float(matthews_corrcoef(y_true, y_pred))
    
    # ROC and PR Area Under Curves
    try:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
    except Exception:
        metrics["roc_auc"] = 0.0

    try:
        prec, rec, _ = precision_recall_curve(y_true, y_prob)
        metrics["pr_auc"] = float(auc(rec, prec))
    except Exception:
        metrics["pr_auc"] = 0.0

    # Log Loss and Brier Score
    try:
        metrics["log_loss"] = float(log_loss(y_true, y_prob, labels=[0, 1]))
    except Exception:
        metrics["log_loss"] = 999.0

    try:
        metrics["brier_score"] = float(brier_score_loss(y_true, y_prob))
    except Exception:
        metrics["brier_score"] = 999.0

    # Specificity, Sensitivity, FPR, FNR
    try:
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        metrics["fpr"] = float(fp / (tn + fp) if (tn + fp) > 0 else 0.0)
        metrics["fnr"] = float(fn / (tp + fn) if (tp + fn) > 0 else 0.0)
        metrics["specificity"] = float(tn / (tn + fp) if (tn + fp) > 0 else 0.0)
        metrics["sensitivity"] = float(tp / (tp + fn) if (tp + fn) > 0 else 0.0)
    except Exception as e:
        logger.warning(f"Failed to calculate confusion statistics: {e}")
        metrics["fpr"] = 0.0
        metrics["fnr"] = 0.0
        metrics["specificity"] = 0.0
        metrics["sensitivity"] = 0.0

    return metrics

