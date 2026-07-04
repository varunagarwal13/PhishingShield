"""Pydantic schemas defining structured explainability evidence logs."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    """Traceable individual detector evidence block."""

    id: str = Field(..., description="Unique Traceable ID of the finding (e.g. URL-001)")
    detector: str = Field(..., description="Identifier of the detector producing the evidence")
    severity: str = Field("LOW", description="LOW, MEDIUM, HIGH, or CRITICAL rating")
    confidence: float = Field(0.5, description="Confidence rating of the specific finding (0 to 1)")
    reason: str = Field(..., description="Natural-language description of the finding")
    details: dict[str, Any] = Field(default_factory=dict, description="Supporting details of the finding")


class RecommendationBlock(BaseModel):
    """Tailored recommendations for end-users and network administrators."""

    user: str = Field(..., description="Actionable recommendation for the user")
    administrator: str = Field(..., description="Evasion/Blocking recommendation for the administrator")


class ExplanationResponse(BaseModel):
    """Standardized machine-readable explanation response model."""

    prediction: str = Field(..., description="Final verdict outcome (PHISHING or BENIGN)")
    risk_score: float = Field(..., description="Calibrated threat score (0 to 100)")
    confidence: float = Field(..., description="Aggregated confidence level (0 to 1)")
    severity: str = Field(..., description="Overall severity rating")
    category: list[str] = Field(default_factory=list, description="High-level threat categories matched")
    summary: str = Field(..., description="Natural-language description of the matched threat campaign")
    evidence: list[EvidenceItem] = Field(default_factory=list, description="Sorted traceback findings list")
    recommendation: RecommendationBlock = Field(..., description="User and Administrator recommendations")
