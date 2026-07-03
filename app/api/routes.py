"""Versioned API routes for the production detector pipeline."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from app.api.dependencies import get_pipeline
from app.pipeline.pipeline import DetectionPipeline
from app.schemas.detection import DetectionRequest, DetectionResponse

router = APIRouter(prefix="/api/v1", tags=["v1"])


@router.post("/analyze", response_model=DetectionResponse)
async def analyze_url(
    payload: DetectionRequest,
    request: Request,
    pipeline: DetectionPipeline = Depends(get_pipeline),
) -> DetectionResponse:
    """Run the modular async detector pipeline."""
    feature_columns = getattr(request.app.state, "FEATURE_COLS", [])
    return await pipeline.analyze(payload, app_state=request.app.state, feature_columns=feature_columns)


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/live")
async def liveness() -> dict:
    return {"status": "alive"}


@router.get("/ready")
async def readiness(request: Request) -> dict:
    return {
        "status": "ready",
        "models": bool(getattr(request.app.state, "rf", None) and getattr(request.app.state, "xgb", None)),
        "redis": bool(getattr(request.app.state, "cache", None)),
    }

