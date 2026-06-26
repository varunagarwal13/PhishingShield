"""Lazy OCR detector."""

from __future__ import annotations

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class OCRDetector(BaseDetector):
    name = "ocr"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        html_analysis = context.shared.get("html_analysis", {})
        should_run = (
            context.request_options.get("force_ocr")
            or html_analysis.get("has_login_form")
            or html_analysis.get("is_image_heavy")
            or context.request_options.get("include_screenshot")
        )
        if not should_run:
            return DetectorResult(
                detector_name=self.name,
                score=0.0,
                confidence=0.5,
                execution_time=0.0,
                severity=severity_for_score(0),
                evidence=["OCR skipped by lazy execution policy"],
                metadata={"skipped": True},
            )
        return DetectorResult(
            detector_name=self.name,
            score=0.0,
            confidence=0.3,
            execution_time=0.0,
            severity=severity_for_score(0),
            evidence=[],
            metadata={"skipped": False, "status": "screenshot_ocr_adapter_ready"},
        )

