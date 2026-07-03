"""Asynchronous detection pipeline."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

from app.detectors.base_detector import BaseDetector, DetectorContext
from app.detectors.dns_detector import DNSDetector
from app.detectors.favicon_detector import FaviconDetector
from app.detectors.heuristic_detector import HeuristicDetector
from app.detectors.html_detector import HtmlDetector
from app.detectors.ml_detector import MLDetector
from app.detectors.ocr_detector import OCRDetector
from app.detectors.reputation_detector import ReputationDetector
from app.detectors.ssl_detector import SSLDetector
from app.detectors.whois_detector import WhoisDetector
from app.pipeline.aggregator import RiskAggregator
from app.pipeline.explanation import ExplanationBuilder
from app.schemas.detection import DetectionRequest, DetectionResponse
from app.services.url_security import UrlSecurityService


DETECTOR_REGISTRY: dict[str, type[BaseDetector]] = {
    "ml": MLDetector,
    "heuristic": HeuristicDetector,
    "reputation": ReputationDetector,
    "html": HtmlDetector,
    "dns": DNSDetector,
    "ssl": SSLDetector,
    "whois": WhoisDetector,
    "favicon": FaviconDetector,
    "ocr": OCRDetector,
}


class DetectionPipeline:
    """Discover, execute, and aggregate enabled detectors."""

    def __init__(
        self,
        url_security: UrlSecurityService,
        services: dict[str, Any],
        aggregator: RiskAggregator,
        explanation_builder: ExplanationBuilder | None = None,
        enabled_detectors: Iterable[str] | None = None,
    ) -> None:
        self.url_security = url_security
        self.services = services
        self.aggregator = aggregator
        self.explanation_builder = explanation_builder or ExplanationBuilder()
        self.detectors = self.discover_detectors(enabled_detectors)

    def discover_detectors(self, enabled_detectors: Iterable[str] | None = None) -> list[BaseDetector]:
        enabled = set(enabled_detectors or DETECTOR_REGISTRY.keys())
        return [detector_cls() for name, detector_cls in DETECTOR_REGISTRY.items() if name in enabled]

    async def analyze(
        self,
        request: DetectionRequest,
        app_state: Any = None,
        feature_columns: list[str] | None = None,
    ) -> DetectionResponse:
        canonical_url = self.url_security.canonicalize(request.url)
        hostname = self.url_security.hostname(canonical_url)
        context = DetectorContext(
            url=request.url,
            canonical_url=canonical_url,
            hostname=hostname,
            registered_domain=self.url_security.registered_domain(hostname),
            app_state=app_state,
            services=self.services,
            feature_columns=feature_columns or [],
            request_options=request.model_dump(),
        )

        first_stage = [detector for detector in self.detectors if detector.name != "ocr"]
        results = await asyncio.gather(*(detector.run(context) for detector in first_stage))
        ocr_detectors = [detector for detector in self.detectors if detector.name == "ocr"]
        if ocr_detectors:
            results.extend(await asyncio.gather(*(detector.run(context) for detector in ocr_detectors)))

        risk_score = self.aggregator.aggregate(results)
        return DetectionResponse(
            url=canonical_url,
            risk_score=risk_score,
            verdict=self.aggregator.verdict_for_score(risk_score),
            reasons=self.explanation_builder.build(results),
            detector_results=results,
            details={
                "registered_domain": context.registered_domain,
                "trusted_domain": self.url_security.trust_match(hostname),
                "homograph_matches": self.url_security.homograph_matches(hostname),
            },
        )

