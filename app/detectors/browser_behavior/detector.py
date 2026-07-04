"""Browser Behavior detector: evaluates dynamic redirects, storage requests, and permission prompts."""

from __future__ import annotations

import logging

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.models.detection import DetectorResult

logger = logging.getLogger("browser_behavior")


class BrowserBehaviorDetector(BaseDetector):
    name = "browser_behavior"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        dom_signals = context.shared.get("puppeteer_dom_signals", {})

        evidence = []
        metadata = {}
        score = 0.0

        # 1. Redirect Chain Analysis
        redirect_chain = dom_signals.get("redirectChain", [])
        if isinstance(redirect_chain, list) and len(redirect_chain) > 1:
            evidence.append(f"Behavior: dynamic redirect chain detected ({len(redirect_chain)} hops)")
            score += min(len(redirect_chain) * 10.0, 30.0)

        # 2. Permission Prompts & Notification Spam
        permission_prompts = dom_signals.get("permissionPrompts", False)
        if permission_prompts:
            evidence.append("Behavior: triggers immediate hardware/notification permission prompts")
            score += 15.0

        # 3. Dynamic Fingerprinting Checks (Canvas/WebRTC)
        canvas_usage = dom_signals.get("canvasFingerprinting", False)
        webrtc_usage = dom_signals.get("webRTCUsage", False)

        if canvas_usage:
            evidence.append("Behavior: canvas read-back detected (fingerprinting indicator)")
            score += 20.0
        if webrtc_usage:
            evidence.append("Behavior: WebRTC connections opened (attempts local IP discovery)")
            score += 15.0

        # 4. Storage & Service Workers
        service_worker_registered = dom_signals.get("serviceWorkerRegistered", False)
        if service_worker_registered:
            evidence.append("Behavior: registers background service worker task on visit")
            score += 10.0

        score = min(score, 100.0)
        confidence = 0.8 if (len(redirect_chain) > 1 or canvas_usage) else 0.5

        metadata.update({
            "redirect_count": len(redirect_chain),
            "redirect_chain": redirect_chain,
            "canvas_fingerprinting": canvas_usage,
            "webrtc_usage": webrtc_usage,
            "service_worker_active": service_worker_registered
        })

        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=confidence,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata=metadata
        )
