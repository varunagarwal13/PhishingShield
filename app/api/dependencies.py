"""Dependency factories for API routes."""

from __future__ import annotations

from fastapi import Request

from app.pipeline.pipeline import DetectionPipeline
from app.services.cache import CacheService
from app.services.puppeteer import PuppeteerService
from app.services.scoring import ScoringService
from app.utils.url_utils import UrlSecurityService
from config.settings import get_settings


def build_pipeline() -> DetectionPipeline:
    """Build the production pipeline instance using modernized services."""
    settings = get_settings()
    url_security = UrlSecurityService(settings.trusted_domains_path)
    cache_service = CacheService(settings.redis_url)
    puppeteer_service = PuppeteerService()
    scoring_service = ScoringService(settings.weights)

    return DetectionPipeline(
        url_security=url_security,
        cache_service=cache_service,
        puppeteer_service=puppeteer_service,
        scoring_service=scoring_service,
    )


def get_pipeline(request: Request) -> DetectionPipeline:
    """Return the app-scoped pipeline, creating it lazily when needed."""
    if not hasattr(request.app.state, "detection_pipeline") or request.app.state.detection_pipeline is None:
        request.app.state.detection_pipeline = build_pipeline()
    return request.app.state.detection_pipeline
