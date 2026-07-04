"""Independent validation suite for PhishingShield threat detectors."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
import time
import numpy as np

from app.detectors import DetectorContext
from app.detectors.url_analysis import UrlAnalysisDetector
from app.detectors.threat_intelligence import ThreatIntelligenceDetector
from app.detectors.visual_hash import VisualHashDetector
from app.detectors.content_analysis import ContentAnalysisDetector
from app.detectors.javascript_intelligence import JavaScriptIntelligenceDetector
from app.detectors.browser_behavior import BrowserBehaviorDetector
from app.detectors.image_analysis import ImageAnalysisDetector
from app.utils.url_utils import UrlSecurityService
from app.models.detection import DetectorResult, Severity

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("detector_validation")


async def run_detectors_validation():
    logger.info("Initializing independent threat detectors validation...")
    
    url_security = UrlSecurityService()
    
    # Define test inputs: 1 benign (Google) and 1 phishing (mock banking)
    targets = [
        {"url": "https://google.com", "label": 0, "is_phish": False},
        {"url": "https://secure-chase-update-verification.net/login.html", "label": 1, "is_phish": True}
    ]
    
    detectors = {
        "url_analysis": UrlAnalysisDetector(),
        "threat_intelligence": ThreatIntelligenceDetector(),
        "visual_hash": VisualHashDetector(),
        "content_analysis": ContentAnalysisDetector(),
        "javascript_intelligence": JavaScriptIntelligenceDetector(),
        "browser_behavior": BrowserBehaviorDetector(),
        "image_analysis": ImageAnalysisDetector()
    }
    
    validation_records = {}
    
    for d_name, detector in detectors.items():
        logger.info(f"Testing detector: {d_name}...")
        
        execution_times = []
        evidence_list = []
        confidences = []
        exceptions = []
        fps = 0
        fns = 0
        schema_verified = True
        
        # Test on targets
        for target in targets:
            url = target["url"]
            is_phish = target["is_phish"]
            
            # Setup context
            stop_event = asyncio.Event()
            context = DetectorContext(
                url=url,
                canonical_url=url_security.canonicalize(url),
                hostname=url_security.hostname(url),
                registered_domain=url_security.registered_domain(url_security.hostname(url)),
                services={"url_security": url_security},
                shared={
                    "stop_event": stop_event,
                    "puppeteer_screenshot": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR42mNkQAEAAD8Aeg5YdxgAAAAASUVORK5CYII=",
                    "puppeteer_page_text": "Verify your bank identity. Input credit card digits to update records.",
                    "puppeteer_dom_signals": {
                        "hasPasswordField": True,
                        "formActionMismatch": True,
                        "rightClickDisabled": True,
                        "devtoolsBlocked": True,
                        "redirectChain": ["https://promo.com", url],
                        "canvasFingerprinting": True
                    }
                }
            )
            
            t_start = time.perf_counter()
            try:
                # Direct check
                res = await detector.run(context)
                t_dur = (time.perf_counter() - t_start) * 1000.0  # in ms
                execution_times.append(t_dur)
                evidence_list.extend(res.evidence)
                confidences.append(res.confidence)
                
                # Verify schema types strictly
                if not isinstance(res.score, float) or not isinstance(res.confidence, float):
                    schema_verified = False
                if not isinstance(res.evidence, list) or not isinstance(res.severity, Severity):
                    schema_verified = False
                
                # Check for false positive (benign flagged as phish >= 50 score)
                if not is_phish and res.score >= 50.0:
                    fps += 1
                # Check for false negative (phish flagged as benign < 10 score due to 0.10 threshold)
                if is_phish and res.score < 10.0:
                    fns += 1
            except Exception as e:
                exceptions.append(str(e))
                logger.error(f"Detector {d_name} raised exception: {e}")
                
        # Force exceptions fallback check
        fallback_works = False
        try:
            # Passing None context forces exception handler to execute
            err_res = await detector.run(None)
            fallback_works = err_res.failed is True and err_res.score == 0.0
        except Exception:
            fallback_works = False
            
        # Estimate metrics
        validation_records[d_name] = {
            "avg_time_ms": float(np.mean(execution_times)) if execution_times else 0.0,
            "avg_confidence": float(np.mean(confidences)) if confidences else 0.0,
            "evidence": list(set(evidence_list))[:5],
            "exceptions": exceptions,
            "fps": fps,
            "fns": fns,
            "schema_verified": schema_verified,
            "fallback_works": fallback_works
        }
        
    # Generate detector_validation.md
    report_path = Path("detector_validation.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# PhishingShield Detector Independent Validation Report\n\n")
        f.write("This document summarizes independent execution profiling, latency performance, and warning triggers for all 7 active detectors.\n\n")
        
        f.write("## 1. Detector Performance Metrics Table\n\n")
        f.write("| Detector Module | Avg Latency (ms) | Confidence Rating | Schema Verified | Fallback Handler | False Positives | False Negatives | Exceptions |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for name, r in validation_records.items():
            exc_status = "None" if not r["exceptions"] else f"{len(r['exceptions'])} raised"
            f.write(f"| **{name}** | {r['avg_time_ms']:.2f}ms | {r['avg_confidence']:.2f} | {'PASS' if r['schema_verified'] else 'FAIL'} | {'PASS' if r['fallback_works'] else 'FAIL'} | {r['fps']} | {r['fns']} | {exc_status} |\n")
            
        f.write("\n## 2. Dynamic Signal Contribution Audits\n\n")
        f.write("- **threat_intelligence**: `LIMITED` contribution when offline or stubbed. Active key credentials must be provided in production configurations.\n")
        f.write("- **visual_hash**: `LIMITED` contribution when screenshot buffers are empty. Dynamic script scanning triggers fallback hash lookups.\n")
        
        f.write("\n## 3. Sample Evidence Mappings Trace\n\n")
        for name, r in validation_records.items():
            f.write(f"### {name} Sample Signals\n")
            if r["evidence"]:
                for ev in r["evidence"]:
                    f.write(f"- \"{ev}\"\n")
            else:
                f.write("- *No evidence returned during standard mock run*\n")
            f.write("\n")
            
    logger.info("✓ Independent validation of detectors finished successfully.")


if __name__ == "__main__":
    asyncio.run(run_detectors_validation())
