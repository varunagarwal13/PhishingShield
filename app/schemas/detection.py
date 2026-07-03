"""Detection schemas shared by API routes, detectors, and pipeline."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class DetectorResult(BaseModel):
    detector_name: str
    score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    execution_time: float = Field(ge=0.0)
    severity: Severity = Severity.info
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    failed: bool = False
    error: str | None = None


class DetectionRequest(BaseModel):
    url: str
    include_screenshot: bool = False
    force_ocr: bool = False


class DetectionResponse(BaseModel):
    url: str
    risk_score: float = Field(ge=0.0, le=100.0)
    verdict: str
    reasons: list[str]
    detector_results: list[DetectorResult]
    details: dict[str, Any] = Field(default_factory=dict)

