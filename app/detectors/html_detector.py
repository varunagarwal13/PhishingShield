"""HTML form, iframe, JavaScript, and hidden-element detector."""

from __future__ import annotations

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.schemas.detection import DetectorResult


class HtmlDetector(BaseDetector):
    name = "html"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        html_service = context.services.get("html")
        html = context.shared.get("html")
        if html is None and html_service:
            html = await html_service.fetch(context.canonical_url)
            context.shared["html"] = html
        analysis = html_service.analyze_html(html or "") if html_service else {}
        evidence: list[str] = []
        score = 0.0

        if analysis.get("has_login_form"):
            score += 35
            evidence.append("Login form detected")
        if analysis.get("password_inputs", 0) > 0:
            score += 20
            evidence.append("Password input present")
        if analysis.get("iframes", 0) > 0:
            score += 10
            evidence.append("Iframe detected")
        if analysis.get("hidden_inputs", 0) >= 3:
            score += 10
            evidence.append("Multiple hidden form fields detected")

        context.shared["html_analysis"] = analysis
        score = min(score, 100.0)
        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=0.8 if html else 0.2,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata={key: value for key, value in analysis.items() if key != "text"},
        )

