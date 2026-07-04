"""Modernized API routing endpoints."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.dependencies import get_pipeline
from app.database.connection import log_feedback
from app.models.detection import DetectionRequest, DetectionResponse
from app.pipeline.pipeline import DetectionPipeline
from app.ai.explainability.evidence import ExplanationResponse

router = APIRouter()
logger = logging.getLogger("phishing_shield")


def validate_input_url(url: str) -> None:
    """Validate request URL before running the pipeline."""
    url = url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL exceeds maximum length of 2048 characters")
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid URL structure: {e}")
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only http and https protocols are supported")


@router.post("/analyse", response_model=DetectionResponse)
@router.post("/api/v1/analyze", response_model=DetectionResponse)
async def analyze_url(
    payload: DetectionRequest,
    pipeline: DetectionPipeline = Depends(get_pipeline),
) -> DetectionResponse:
    """Run the optimized phishing detection pipeline."""
    validate_input_url(payload.url)
    logger.info(f"API Request to analyze: {payload.url[:80]}")
    return await pipeline.analyze(payload)


@router.post("/feedback")
async def feedback(request: Request) -> dict:
    """Log user feedback (e.g. proceeded bypass, false positive flags)."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    url = body.get("url", "").strip()
    action = body.get("action", "").strip() or body.get("feedback", "").strip()
    
    if not url or not action:
        raise HTTPException(status_code=400, detail="url and action/feedback are required")

    # DB logging delegated to dedicated connection module (no DB logic in route)
    log_feedback(url, action)
    return {"ok": True}


@router.post("/cache/clear")
async def cache_clear(request: Request, pipeline: DetectionPipeline = Depends(get_pipeline)) -> dict:
    """Clear cached entries for a URL (requested after a PIN override)."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    await pipeline.cache_service.clear_url_cache(url)
    return {"ok": True}


@router.get("/health")
@router.get("/api/v1/health")
async def health(request: Request) -> dict:
    """Versioned liveness and diagnostic checker."""
    pipeline = get_pipeline(request)
    r = await pipeline.cache_service.get_redis()
    return {
        "status": "ok",
        "redis": "connected" if r is not None else "disconnected",
        "timestamp": datetime.now(UTC).isoformat()
    }


@router.get("/live")
@router.get("/api/v1/live")
async def live() -> dict:
    """Liveness check."""
    return {"status": "alive"}


@router.get("/ready")
@router.get("/api/v1/ready")
async def readiness(request: Request) -> dict:
    """Readiness endpoint verifying core subsystems."""
    pipeline = get_pipeline(request)
    r = await pipeline.cache_service.get_redis()
    state = request.app.state
    
    models_ready = False
    if state and hasattr(state, "rf") and hasattr(state, "xgb"):
        models_ready = state.rf is not None and state.xgb is not None

    return {
        "status": "ready",
        "models": models_ready,
        "redis": r is not None,
        "pipeline": pipeline is not None
    }


@router.get("/analysis/explanation", response_model=ExplanationResponse)
async def get_analysis_explanation(
    url: str,
    pipeline: DetectionPipeline = Depends(get_pipeline)
) -> ExplanationResponse:
    """Get structured AI analysis and prioritized reasons."""
    validate_input_url(url)
    return await pipeline.get_explanation(url)


@router.get("/analysis/report")
async def get_analysis_report(
    url: str,
    pipeline: DetectionPipeline = Depends(get_pipeline)
):
    """Get human-readable Markdown analysis report."""
    from fastapi.responses import PlainTextResponse
    from app.ai.explainability.explanation_engine import ExplanationEngine
    validate_input_url(url)
    explanation = await pipeline.get_explanation(url)
    md_content = ExplanationEngine.render_markdown(explanation)
    return PlainTextResponse(content=md_content, media_type="text/markdown")


@router.get("/analysis/evidence")
async def get_analysis_evidence(
    url: str,
    pipeline: DetectionPipeline = Depends(get_pipeline)
):
    """Get machine-readable evidence array only."""
    validate_input_url(url)
    explanation = await pipeline.get_explanation(url)
    return explanation.evidence
