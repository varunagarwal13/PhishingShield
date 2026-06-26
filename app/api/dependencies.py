"""Dependency factories for API routes."""

from __future__ import annotations

from typing import Any

from fastapi import Request

from app.config.settings import get_settings
from app.pipeline.aggregator import RiskAggregator
from app.pipeline.explanation import ExplanationBuilder
from app.pipeline.pipeline import DetectionPipeline
from app.services.feature_service import FeatureService
from app.services.html_service import HtmlService
from app.services.url_security import UrlSecurityService
from app.services.vt_service import VirusTotalService


def build_pipeline(app_state: Any = None) -> DetectionPipeline:
    """Build a pipeline instance from settings and app state."""
    settings = get_settings()
    url_security = UrlSecurityService(settings.trusted_domains_path)
    services = {
        "html": HtmlService(url_security, settings.http_timeout_seconds, settings.verify_ssl),
        "virustotal": VirusTotalService(settings.vt_api_key, settings.http_timeout_seconds),
        "features": FeatureService(),
    }
    return DetectionPipeline(
        url_security=url_security,
        services=services,
        aggregator=RiskAggregator(settings.detector_weights),
        explanation_builder=ExplanationBuilder(),
        enabled_detectors=settings.enabled_detectors,
    )


def get_pipeline(request: Request) -> DetectionPipeline:
    """Return the app-scoped pipeline, creating it lazily when needed."""
    if not hasattr(request.app.state, "detection_pipeline"):
        request.app.state.detection_pipeline = build_pipeline(request.app.state)
    return request.app.state.detection_pipeline

