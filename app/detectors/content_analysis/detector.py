"""Content Analysis detector: DOM layout properties and Semantic NLP scam classification."""

from __future__ import annotations

import logging
from bs4 import BeautifulSoup
import aiohttp

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.models.detection import DetectorResult
from app.ai.embeddings import classify_text_semantics
from app.utils.url_utils import UrlSecurityService

logger = logging.getLogger("content_analysis")

DOM_PHISHING_PHRASES = [
    "verify your identity", "suspicious activity detected", "reset your security",
    "account access locked", "confirm card credentials", "bank security notification"
]


class ContentAnalysisDetector(BaseDetector):
    name = "content_analysis"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        url = context.canonical_url
        page_text = context.shared.get("puppeteer_page_text", "")
        dom_signals = context.shared.get("puppeteer_dom_signals", {})

        # Fallback: if no page text, fetch page content safely
        if not page_text:
            url_sec = context.services.get("url_security") or UrlSecurityService()
            if not url_sec.is_private_host(url):
                page_text = await self._fetch_page_text(url)

        evidence = []
        metadata = {}
        score = 0.0

        # ── 1. DOM Analysis ──
        # Check layout properties returned from Puppeteer
        if dom_signals:
            if dom_signals.get("hasPasswordField"):
                evidence.append("DOM: contains credentials harvesting input fields (password)")
                score += 15.0
            if dom_signals.get("iframeAbuse"):
                evidence.append("DOM: cross-origin hidden iframes detected (potential frame hijacking)")
                score += 20.0
            if dom_signals.get("formActionMismatch"):
                evidence.append("DOM: form submission redirects to foreign hostname target")
                score += 20.0

        # Inspect text for common phishing keywords
        detected_phrases = []
        if page_text:
            text_lower = page_text.lower()
            for phrase in DOM_PHISHING_PHRASES:
                if phrase in text_lower:
                    detected_phrases.append(phrase)
            
            if detected_phrases:
                evidence.append(f"DOM Text: suspicious phishing phrasing detected ({', '.join(detected_phrases[:2])})")
                score += 15.0

        # ── 2. Semantic NLP Classifier ──
        semantic_scores = {}
        highest_semantic_match = None
        highest_semantic_score = 0.0

        if page_text:
            try:
                # Classifies page text against neural scam profiles
                semantic_scores = classify_text_semantics(page_text)
                for profile, p_score in semantic_scores.items():
                    if p_score > highest_semantic_score:
                        highest_semantic_score = p_score
                        highest_semantic_match = profile

                if highest_semantic_score >= 0.70:
                    score += 35.0
                    evidence.append(
                        f"Semantic NLP Match: content matches '{highest_semantic_match.replace('_', ' ')}' "
                        f"phishing profile (confidence: {highest_semantic_score*100:.1f}%)"
                    )
            except Exception as e:
                logger.error(f"NLP semantic analysis failed: {e}")

        score = min(score, 100.0)

        metadata.update({
            "detected_phrases": detected_phrases,
            "semantic_scores": semantic_scores,
            "highest_semantic_match": highest_semantic_match,
            "highest_semantic_score": highest_semantic_score,
            "has_login_elements": dom_signals.get("hasPasswordField", False)
        })

        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=max(highest_semantic_score, 0.7) if page_text else 0.5,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata=metadata
        )

    async def _fetch_page_text(self, url: str) -> str:
        try:
            timeout = aiohttp.ClientTimeout(total=4)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status != 200:
                        return ""
                    html = await resp.text()
                    soup = BeautifulSoup(html, "html.parser")
                    for tag in soup(["script", "style", "meta", "link"]):
                        tag.decompose()
                    return soup.get_text(separator=" ", strip=True)[:5000]
        except Exception:
            return ""
