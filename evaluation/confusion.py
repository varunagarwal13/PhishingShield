"""Confusion matrix extraction and parsing for model validation evaluation."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import confusion_matrix


def get_confusion_stats(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, int]:
    """Calculate and return TN, FP, FN, TP from predictions."""
    try:
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        return {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        }
    except Exception:
        return {"tn": 0, "fp": 0, "fn": 0, "tp": 0}
