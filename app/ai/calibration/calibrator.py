"""Calibrator helper ensuring model outputs are scaled and bounded."""

from __future__ import annotations


def calibrate_probability(raw_prob: float) -> float:
    """Clamp probability bounds and ensure value conforms to a clean float range [0.0, 1.0]."""
    try:
        val = float(raw_prob)
        return max(0.0, min(val, 1.0))
    except (ValueError, TypeError):
        return 0.0
