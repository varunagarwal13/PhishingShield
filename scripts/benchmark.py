"""Performance Benchmarking Script: Measures execution timings and memory footprints."""

from __future__ import annotations

import asyncio
import time
import logging
from unittest.mock import AsyncMock, MagicMock

# Standard modules imports
from app.utils.url_utils import UrlSecurityService
from app.services.cache import CacheService
from app.services.scoring import ScoringService
from app.pipeline.pipeline import DetectionPipeline
from app.models.detection import DetectionRequest, DetectorResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("performance_benchmarks")

TEST_URLS = [
    "https://google.com",
    "http://secure-paypal-verify-login.net/signin",
    "https://microsoft-office365-upgrade.info/login.html"
]


async def run_benchmarks() -> None:
    logger.info("Initializing PhishingShield Performance Benchmark...")

    url_security = UrlSecurityService()
    cache_service = CacheService()
    scoring_service = ScoringService()

    # Mock Puppeteer backend to keep benchmarks purely offline
    puppeteer_service = MagicMock()
    puppeteer_service.get_page_data = AsyncMock(return_value={
        "screenshot": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR42mNkQAEAAD8Aeg5YdxgAAAAASUVORK5CYII=",
        "domSignals": {
            "hasPasswordField": True,
            "formActionMismatch": True,
            "iframeAbuse": False,
            "rightClickDisabled": True,
            "devtoolsBlocked": True,
            "redirectChain": ["https://promo-redirect.com", "https://phishing-landing.com"],
            "canvasFingerprinting": True
        },
        "pageText": "Please verify immediately your identity to avoid account lock."
    })

    pipeline = DetectionPipeline(
        url_security=url_security,
        cache_service=cache_service,
        puppeteer_service=puppeteer_service,
        scoring_service=scoring_service
    )

    # Mock external threat intelligence lookup to avoid rate limits
    pipeline.detectors["threat_intelligence"].analyze = AsyncMock(
        return_value=DetectorResult(
            detector_name="threat_intelligence",
            score=0.0,
            confidence=0.5,
            execution_time=0.0,
            evidence=[],
            metadata={}
        )
    )

    # 1. Warm-up phase (pre-load lazy models)
    logger.info("Pre-loading lazy models for warm-up...")
    from app.ai.loaders import ModelLoader
    start_load = time.perf_counter()
    ModelLoader.get_structured_model()
    ModelLoader.get_nlp_model()
    ModelLoader.get_ocr_reader()
    load_time = time.perf_counter() - start_load
    logger.info(f"✓ Model loading time: {load_time * 1000:.2f} ms")

    # 2. Benchmark URL requests
    logger.info("Running benchmarks over test URLs...")
    for idx, url in enumerate(TEST_URLS, 1):
        req = DetectionRequest(url=url)
        
        start_total = time.perf_counter()
        response = await pipeline.analyze(req)
        total_latency = (time.perf_counter() - start_total) * 1000

        print(f"\n[URL #{idx}] {url}")
        print(f"  Verdict:       {response.verdict}")
        print(f"  Risk Score:    {response.risk_score}")
        print(f"  Scanned reasons: {response.reasons}")
        print(f"  Total Latency: {total_latency:.2f} ms")

        # Expose individual detector latencies
        if response.detector_results:
            print("  Sub-Detector Timings:")
            for res in response.detector_results:
                print(f"    - {res.detector_name}: {res.execution_time * 1000:.2f} ms")

    print("\n[OK] Performance benchmark run finished successfully.")


if __name__ == "__main__":
    asyncio.run(run_benchmarks())
