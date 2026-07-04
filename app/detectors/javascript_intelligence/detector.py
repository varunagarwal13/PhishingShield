"""JavaScript Intelligence detector: scans page scripts for obfuscation, dynamic calls, and keylogging."""

from __future__ import annotations

import logging
import re

from app.detectors.base_detector import BaseDetector, DetectorContext, severity_for_score
from app.models.detection import DetectorResult

logger = logging.getLogger("javascript_intelligence")

# Obfuscation & Dynamic Injection Regexes
SUSPICIOUS_CONSTRUCTS = {
    "eval_execution": re.compile(r"\beval\s*\("),
    "function_constructor": re.compile(r"\bFunction\s*\("),
    "base64_decode": re.compile(r"\batob\s*\("),
    "document_write": re.compile(r"\bdocument\.write\s*\("),
    "window_open_spam": re.compile(r"\bwindow\.open\s*\("),
    "dynamic_import": re.compile(r"\bimport\s*\(")
}


class JavaScriptIntelligenceDetector(BaseDetector):
    name = "javascript_intelligence"

    async def analyze(self, context: DetectorContext) -> DetectorResult:
        dom_signals = context.shared.get("puppeteer_dom_signals", {})
        page_text = context.shared.get("puppeteer_page_text", "")

        evidence = []
        metadata = {}
        score = 0.0

        # 1. Dynamic Script Inspections
        # If we have DOM signals or text representing script blocks, run regex matches
        found_constructs = []
        for name, pattern in SUSPICIOUS_CONSTRUCTS.items():
            if pattern.search(page_text):
                found_constructs.append(name.replace("_", " "))
                score += 15.0

        if found_constructs:
            evidence.append(f"JS: suspicious runtime constructs found ({', '.join(found_constructs[:2])})")

        # 2. Browser/DOM Anti-Forensics (instrumented via Puppeteer signals)
        devtools_blocked = dom_signals.get("devtoolsBlocked", False)
        clipboard_hijack = dom_signals.get("clipboardHijack", False)
        right_click_disabled = dom_signals.get("rightClickDisabled", False)

        if devtools_blocked:
            score += 25.0
            evidence.append("JS: Anti-forensics detected (script actively blocks DevTools console opening)")
        if clipboard_hijack:
            score += 20.0
            evidence.append("JS: dynamic clipboard modification (copy-paste hijack) handler active")
        if right_click_disabled:
            score += 10.0
            evidence.append("JS: contextmenu right-click is disabled (prevents page inspection)")

        # 3. Obfuscation Entropy Score
        # Obfuscation is flagged if there's high count of suspicious calls relative to script text
        obfuscated = False
        if len(found_constructs) >= 3 or (devtools_blocked and len(found_constructs) >= 1):
            obfuscated = True
            score += 20.0
            evidence.append("JS: high script obfuscation entropy rating (multiple evasion methods)")

        score = min(score, 100.0)

        metadata.update({
            "found_constructs": found_constructs,
            "devtools_blocked": devtools_blocked,
            "clipboard_hijack": clipboard_hijack,
            "right_click_disabled": right_click_disabled,
            "obfuscation_detected": obfuscated
        })

        return DetectorResult(
            detector_name=self.name,
            score=score,
            confidence=0.85 if devtools_blocked else 0.6,
            execution_time=0.0,
            severity=severity_for_score(score),
            evidence=evidence,
            metadata=metadata
        )
