"""Modernized Asynchronous Detection Pipeline implementing the strict PhishingShield workflow."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import socket
import ssl
from datetime import UTC, datetime

import whois

from app.database.connection import SessionLocal, ThreatLog
from app.detectors.base_detector import BaseDetector, DetectorContext
from app.detectors.content_analysis import ContentAnalysisDetector
from app.detectors.image_analysis import ImageAnalysisDetector
from app.detectors.threat_intelligence import ThreatIntelligenceDetector
from app.detectors.url_analysis import UrlAnalysisDetector
from app.detectors.visual_hash import VisualHashDetector
from app.detectors.javascript_intelligence import JavaScriptIntelligenceDetector
from app.detectors.browser_behavior import BrowserBehaviorDetector

from app.models.detection import DetectionRequest, DetectionResponse, DetectorResult
from app.services.cache import CacheService
from app.services.puppeteer import PuppeteerService
from app.services.scoring import ScoringService
from app.utils.url_utils import UrlSecurityService, extract_domain
from config.constants import RISKY_TLDS

logger = logging.getLogger("phishing_shield")


class DetectionPipeline:
    """Orchestrates caching, pre-checks, fast checks, parallel detectors, and scoring."""

    def __init__(
        self,
        url_security: UrlSecurityService,
        cache_service: CacheService,
        puppeteer_service: PuppeteerService,
        scoring_service: ScoringService,
    ) -> None:
        self.url_security = url_security
        self.cache_service = cache_service
        self.puppeteer_service = puppeteer_service
        self.scoring_service = scoring_service

        # Instantiate consolidated detectors
        self.detectors: dict[str, BaseDetector] = {
            "url_analysis": UrlAnalysisDetector(),
            "threat_intelligence": ThreatIntelligenceDetector(),
            "visual_hash": VisualHashDetector(),
            "content_analysis": ContentAnalysisDetector(),
            "javascript_intelligence": JavaScriptIntelligenceDetector(),
            "browser_behavior": BrowserBehaviorDetector(),
            "image_analysis": ImageAnalysisDetector(),
        }

    async def analyze(self, request: DetectionRequest, app_state: any = None) -> DetectionResponse:
        url = request.url.strip()
        started_at = datetime.now(UTC)

        # ── 1. Redis Cache ──
        cached_verdict = await self.cache_service.check_cache(url)
        if cached_verdict:
            logger.info(f"Cache HIT for URL: {url[:80]} -> verdict={cached_verdict.get('action')}")
            details = cached_verdict.get("details") or {}
            if "registered_domain" not in details:
                hostname = self.url_security.hostname(url)
                details["registered_domain"] = self.url_security.registered_domain(hostname)
            return DetectionResponse(
                url=url,
                risk_score=cached_verdict.get("score", 0.0),
                verdict=cached_verdict.get("action", "allow").upper(),
                reasons=cached_verdict.get("signals", []),
                detector_results=[],
                details=details
            )

        # ── 2. URL Pre-check (Alexa / Known good) ──
        hostname = self.url_security.hostname(url)
        registered_domain = self.url_security.registered_domain(hostname)

        self.url_security.reload_trusted_domains()

        if self.url_security.is_safe(hostname):
            logger.info(f"Pre-check ALLOW (trusted domain): {hostname}")
            verdict = {"action": "allow", "score": 0, "signals": [], "all_signals": []}
            await self.cache_service.write_cache(url, verdict, ttl=21600)
            return DetectionResponse(
                url=url,
                risk_score=0.0,
                verdict="ALLOW",
                reasons=[],
                detector_results=[],
                details={
                    "registered_domain": registered_domain,
                    "trusted_domain": hostname,
                    "precheck_hit": True
                }
            )

        # ── 3. Fast Definitive Checks (WHOIS, SSL cert, entropy, TLD) ──
        fast_result = await self._run_fast_checks(url, hostname)
        if fast_result.get("early_exit"):
            logger.info(f"Early exit BLOCK on fast checks for URL: {url[:80]}")
            verdict = fast_result["verdict"]
            await self.cache_service.write_cache(url, verdict, ttl=86400)
            await self._log_to_db(url, verdict, started_at, details={"fast_checks": fast_result})
            return DetectionResponse(
                url=url,
                risk_score=verdict["score"],
                verdict=verdict["action"].upper(),
                reasons=verdict["signals"],
                detector_results=[],
                details={
                    "registered_domain": registered_domain,
                    "fast_checks_hit": True
                }
            )

        # ── 4. Parallel Detector Executor ──
        stop_event = asyncio.Event()
        context = DetectorContext(
            url=url,
            canonical_url=self.url_security.canonicalize(url),
            hostname=hostname,
            registered_domain=registered_domain,
            app_state=app_state,
            services={
                "puppeteer": self.puppeteer_service,
                "url_security": self.url_security
            },
            shared={
                "stop_event": stop_event
            }
        )

        # Execute Stage 1 detectors in parallel (connection pooling active)
        stage_1_detectors = [
            "url_analysis", "threat_intelligence", "visual_hash",
            "content_analysis", "javascript_intelligence", "browser_behavior"
        ]
        
        stage_1_results: list[DetectorResult] = await asyncio.gather(
            *(self.detectors[d_name].run(context) for d_name in stage_1_detectors),
            return_exceptions=True
        )

        mapped_results: dict[str, dict] = {}
        detector_objs: list[DetectorResult] = []

        for name, res in zip(stage_1_detectors, stage_1_results, strict=True):
            if isinstance(res, DetectorResult):
                mapped_results[name] = {
                    "score": res.score,
                    "signals": res.evidence,
                    "metadata": res.metadata,
                    "confidence": res.confidence
                }
                detector_objs.append(res)
            else:
                logger.error(f"Detector {name} failed: {res}")
                mapped_results[name] = {}

        # Execute Stage 2 (Image Analysis) if stop_event has not fired
        image_res_obj = None
        if not stop_event.is_set():
            image_res_obj = await self.detectors["image_analysis"].run(context)
            if isinstance(image_res_obj, DetectorResult):
                mapped_results["image_analysis"] = {
                    "score": image_res_obj.score,
                    "signals": image_res_obj.evidence,
                    "metadata": image_res_obj.metadata,
                    "confidence": image_res_obj.confidence
                }
                detector_objs.append(image_res_obj)
            else:
                mapped_results["image_analysis"] = {}

        # ── 5. Risk Scoring Engine ──
        verdict = self.scoring_service.compute_score(mapped_results, fast_result)

        # ── 5.5. Compile and Cache AI Explanation ──
        from app.ai.explainability.explanation_engine import ExplanationEngine
        explanation_obj = ExplanationEngine.compile_explanation(
            prediction=verdict["action"],
            risk_score=verdict["score"],
            confidence=verdict["confidence"],
            detector_outputs=mapped_results,
            fast_checks=fast_result
        )
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        ttl = 86400 if verdict["action"] == "block" else 3600
        
        # Save to Redis
        redis = await self.cache_service.get_redis()
        if redis is not None:
            try:
                import numpy as np
                class NumpyEncoder(json.JSONEncoder):
                    def default(self, obj):
                        if isinstance(obj, (np.integer, np.floating)):
                            return obj.item()
                        if isinstance(obj, np.ndarray):
                            return obj.tolist()
                        return super().default(obj)
                await redis.setex(
                    f"explanation:{url_hash}",
                    ttl,
                    json.dumps(explanation_obj.model_dump(), cls=NumpyEncoder)
                )
            except Exception as e:
                logger.warning(f"Failed to cache explanation payload: {e}")

        # ── 6. Cache Result ──
        await self.cache_service.write_cache(url, verdict, ttl=ttl)


        # ── 7. Database Log ──
        execution_time = (datetime.now(UTC) - started_at).total_seconds()
        
        html_hash = None
        page_text = context.shared.get("puppeteer_page_text", "")
        if page_text:
            html_hash = hashlib.sha256(page_text.encode()).hexdigest()

        await self._log_to_db(
            url=url,
            verdict=verdict,
            started_at=started_at,
            detector_outputs=detector_objs,
            html_hash=html_hash
        )

        return DetectionResponse(
            url=url,
            risk_score=verdict["score"],
            verdict=verdict["action"].upper(),
            reasons=verdict["signals"],
            detector_results=detector_objs,
            details={
                "registered_domain": registered_domain,
                "trusted_domain": self.url_security.trust_match(hostname),
                "homograph_matches": self.url_security.homograph_matches(hostname),
                "execution_time_seconds": round(execution_time, 3)
            }
        )

    async def _run_fast_checks(self, url: str, hostname: str) -> dict:
        """Run fast, non-blocking pre-checks."""
        score = 0
        signals = []

        from training.feature_engineering.features import shannon_entropy
        ext = extract_domain(hostname)
        domain = ext.domain.lower() if ext.domain else ""
        entropy = shannon_entropy(domain)
        if entropy > 3.8:
            score += 10
            signals.append("High domain entropy (AI-generated pattern)")

        tld = "." + ext.suffix.lower() if ext.suffix else ""
        if ext.suffix and ext.suffix in RISKY_TLDS:
            score += 15
            signals.append(f"Suspicious TLD ({tld})")

        whois_age, cert_age = await asyncio.gather(
            self._get_domain_age_days(hostname),
            self._get_cert_age_hours(hostname),
            return_exceptions=True
        )

        if isinstance(whois_age, int):
            if whois_age == 0:
                score += 30
                signals.append("Domain registered today")
            elif whois_age <= 3:
                score += 30
                signals.append(f"Domain registered {whois_age} day(s) ago")
            elif whois_age <= 7:
                score += 20
                signals.append(f"Very new domain ({whois_age} days old)")
            elif whois_age <= 30:
                score += 10
                signals.append(f"New domain ({whois_age} days old)")
        else:
            score += 15
            signals.append("No WHOIS record found")

        if isinstance(cert_age, int):
            if cert_age == 0:
                score += 20
                signals.append("SSL certificate issued in the last hour")
            elif cert_age <= 24:
                score += 20
                signals.append(f"SSL certificate issued {cert_age}h ago")
            elif cert_age <= 168:
                score += 10
                signals.append("SSL certificate less than 7 days old")

        if score >= 50:
            verdict = {
                "action": "block",
                "score": min(score, 100),
                "signals": signals[:3],
                "all_signals": signals,
            }
            return {"early_exit": True, "verdict": verdict, "partial_score": score, "signals": signals}

        return {"early_exit": False, "partial_score": score, "signals": signals}

    async def _get_domain_age_days(self, domain: str) -> int:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._whois_lookup, domain),
                timeout=3.0
            )
        except Exception as e:
            raise Exception("WHOIS lookup failed") from e

    def _whois_lookup(self, domain: str) -> int:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date is None:
                raise Exception("No creation date")
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=UTC)
            now = datetime.now(UTC)
            return max(0, (now - creation_date).days)
        except Exception as e:
            raise Exception(f"WHOIS failed: {e}") from e

    async def _get_cert_age_hours(self, domain: str) -> int:
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._ssl_cert_age, domain),
                timeout=3.0
            )
        except Exception as e:
            raise Exception("SSL lookup failed") from e

    def _ssl_cert_age(self, domain: str) -> int:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock, \
                 ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
            not_before_str = cert.get("notBefore", "")
            if not not_before_str:
                raise Exception("No notBefore")
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_before = not_before.replace(tzinfo=UTC)
            now = datetime.now(UTC)
            return max(0, int((now - not_before).total_seconds() / 3600))
        except Exception as e:
            raise Exception(f"SSL check failed: {e}") from e

    async def _log_to_db(
        self,
        url: str,
        verdict: dict,
        started_at: datetime,
        detector_outputs: list[DetectorResult] | None = None,
        html_hash: str | None = None,
        details: dict | None = None
    ) -> None:
        try:
            import numpy as np
            class NumpyEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, (np.integer, np.floating)):
                        return obj.item()
                    if isinstance(obj, np.ndarray):
                        return obj.tolist()
                    return super().default(obj)

            execution_time = (datetime.now(UTC) - started_at).total_seconds()
            
            outputs_serialized = []
            if detector_outputs:
                for out in detector_outputs:
                    outputs_serialized.append(out.model_dump())

            db_verdict = verdict.get("action", "allow").upper()
            db_score = verdict.get("score", 0)
            db_signals = json.dumps(verdict.get("signals", []), cls=NumpyEncoder)

            db = SessionLocal()
            try:
                log = ThreatLog(
                    url=url[:2048],
                    score=db_score,
                    verdict=db_verdict,
                    signals=db_signals,
                    cached=0,
                    detector_outputs=json.dumps(outputs_serialized, cls=NumpyEncoder),
                    execution_time=round(execution_time, 4),
                    html_hash=html_hash,
                    timestamp=started_at
                )
                db.add(log)
                db.commit()
            except Exception as e:
                db.rollback()
                logger.error(f"Database write transaction failed: {e}")
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to write database logs: {e}")

    async def get_explanation(self, url: str) -> ExplanationResponse:
        """Fetch structured AI explanation from cache, or run analysis on the fly if missing."""
        url_hash = hashlib.sha256(url.strip().encode()).hexdigest()
        redis = await self.cache_service.get_redis()
        if redis is not None:
            try:
                cached = await redis.get(f"explanation:{url_hash}")
                if cached:
                    data = json.loads(cached)
                    from app.ai.explainability.evidence import ExplanationResponse
                    return ExplanationResponse(**data)
            except Exception as e:
                logger.warning(f"Failed to load cached explanation: {e}")

        # Fallback: run analyze on the fly
        await self.analyze(DetectionRequest(url=url))
        
        # Load from cache again
        if redis is not None:
            cached = await redis.get(f"explanation:{url_hash}")
            if cached:
                data = json.loads(cached)
                from app.ai.explainability.evidence import ExplanationResponse
                return ExplanationResponse(**data)

        # Failure fallback
        from app.ai.explainability.evidence import ExplanationResponse, RecommendationBlock
        return ExplanationResponse(
            prediction="ALLOW",
            risk_score=0.0,
            confidence=0.5,
            severity="LOW",
            category=[],
            summary="No threat detected or failed to retrieve analysis logs.",
            evidence=[],
            recommendation=RecommendationBlock(
                user="Standard web browsing practices apply.",
                administrator="No containment action required."
            )
        )

