"""Explanation Engine: Core orchestrator mapping and formatting detection evidence reports."""

from __future__ import annotations

import logging
from typing import Any

from app.ai.explainability.evidence import EvidenceItem, ExplanationResponse
from app.ai.explainability.risk_taxonomy import classify_categories
from app.ai.explainability.mitre_mapping import get_mitre_mapping
from app.ai.explainability.recommendations import generate_recommendations

logger = logging.getLogger("explanation_engine")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Mapping of keywords in evidence strings to structured metadata parameters
EVIDENCE_RULES = [
    # ── URL Analysis ──
    {"kw": "ip address", "id": "URL-001", "sev": "HIGH", "conf": 0.95, "det": "url_analysis"},
    {"kw": "resembles a popular brand", "id": "URL-002", "sev": "HIGH", "conf": 0.85, "det": "url_analysis"},
    {"kw": "exact match for a popular brand", "id": "URL-002", "sev": "HIGH", "conf": 0.95, "det": "url_analysis"},
    {"kw": "character entropy", "id": "URL-003", "sev": "MEDIUM", "conf": 0.80, "det": "url_analysis"},
    {"kw": "ratio of numbers", "id": "URL-004", "sev": "LOW", "conf": 0.70, "det": "url_analysis"},
    {"kw": "punycode", "id": "URL-005", "sev": "HIGH", "conf": 0.90, "det": "url_analysis"},
    {"kw": "mixed international scripts", "id": "URL-006", "sev": "HIGH", "conf": 0.90, "det": "url_analysis"},
    {"kw": "non-standard port", "id": "URL-007", "sev": "LOW", "conf": 0.75, "det": "url_analysis"},
    {"kw": "tld flagged", "id": "URL-008", "sev": "MEDIUM", "conf": 0.85, "det": "url_analysis"},
    {"kw": "predicted", "id": "URL-009", "sev": "HIGH", "conf": 0.90, "det": "url_analysis"},
    {"kw": "parameter entropy", "id": "URL-010", "sev": "MEDIUM", "conf": 0.80, "det": "url_analysis"},
    {"kw": "nested url", "id": "URL-011", "sev": "HIGH", "conf": 0.90, "det": "url_analysis"},
    {"kw": "repeated character", "id": "URL-012", "sev": "LOW", "conf": 0.70, "det": "url_analysis"},
    {"kw": "uppercase letters", "id": "URL-013", "sev": "LOW", "conf": 0.70, "det": "url_analysis"},


    # ── Threat Intelligence ──
    {"kw": "virustotal early exit", "id": "TI-001", "sev": "CRITICAL", "conf": 1.0, "det": "threat_intelligence"},
    {"kw": "virustotal: flagged", "id": "TI-001", "sev": "HIGH", "conf": 0.95, "det": "threat_intelligence"},
    {"kw": "google safe browsing", "id": "TI-002", "sev": "CRITICAL", "conf": 1.0, "det": "threat_intelligence"},
    {"kw": "phishtank", "id": "TI-003", "sev": "CRITICAL", "conf": 1.0, "det": "threat_intelligence"},
    {"kw": "openphish", "id": "TI-004", "sev": "HIGH", "conf": 0.95, "det": "threat_intelligence"},
    {"kw": "urlhaus", "id": "TI-005", "sev": "CRITICAL", "conf": 1.0, "det": "threat_intelligence"},
    {"kw": "abuseipdb", "id": "TI-006", "sev": "HIGH", "conf": 0.90, "det": "threat_intelligence"},
    {"kw": "alienvault", "id": "TI-007", "sev": "MEDIUM", "conf": 0.85, "det": "threat_intelligence"},

    # ── Visual Intelligence ──
    {"kw": "perceptual hashing match", "id": "VIS-001", "sev": "CRITICAL", "conf": 0.98, "det": "visual_hash"},
    {"kw": "clip semantic visual match", "id": "VIS-002", "sev": "CRITICAL", "conf": 0.95, "det": "visual_hash"},
    {"kw": "password field present", "id": "DOM-001", "sev": "HIGH", "conf": 0.90, "det": "visual_hash"},
    {"kw": "form submission points to mismatch", "id": "DOM-003", "sev": "HIGH", "conf": 0.90, "det": "visual_hash"},

    # ── Content Analysis ──
    {"kw": "credentials harvesting input", "id": "DOM-001", "sev": "HIGH", "conf": 0.90, "det": "content_analysis"},
    {"kw": "hidden iframes detected", "id": "DOM-002", "sev": "MEDIUM", "conf": 0.85, "det": "content_analysis"},
    {"kw": "redirects to foreign hostname", "id": "DOM-003", "sev": "HIGH", "conf": 0.90, "det": "content_analysis"},
    {"kw": "phishing phrasing detected", "id": "DOM-004", "sev": "MEDIUM", "conf": 0.80, "det": "content_analysis"},
    {"kw": "semantic nlp match", "id": "NLP-001", "sev": "HIGH", "conf": 0.90, "det": "content_analysis"},

    # ── JavaScript Intelligence ──
    {"kw": "right-click is disabled", "id": "JS-001", "sev": "MEDIUM", "conf": 0.80, "det": "javascript_intelligence"},
    {"kw": "clipboard modification", "id": "JS-002", "sev": "HIGH", "conf": 0.85, "det": "javascript_intelligence"},
    {"kw": "blocks devtools", "id": "JS-003", "sev": "HIGH", "conf": 0.90, "det": "javascript_intelligence"},
    {"kw": "obfuscation entropy", "id": "JS-004", "sev": "HIGH", "conf": 0.90, "det": "javascript_intelligence"},
    {"kw": "suspicious runtime constructs", "id": "JS-005", "sev": "HIGH", "conf": 0.85, "det": "javascript_intelligence"},

    # ── Browser Behavior ──
    {"kw": "redirect chain detected", "id": "BEH-001", "sev": "MEDIUM", "conf": 0.80, "det": "browser_behavior"},
    {"kw": "permission prompts", "id": "BEH-002", "sev": "MEDIUM", "conf": 0.80, "det": "browser_behavior"},
    {"kw": "canvas read-back", "id": "BEH-003", "sev": "MEDIUM", "conf": 0.85, "det": "browser_behavior"},
    {"kw": "webrtc connections", "id": "BEH-004", "sev": "MEDIUM", "conf": 0.80, "det": "browser_behavior"},
    {"kw": "registers background service", "id": "BEH-005", "sev": "LOW", "conf": 0.75, "det": "browser_behavior"},

    # ── Image Analysis ──
    {"kw": "ocr:", "id": "OCR-001", "sev": "HIGH", "conf": 0.85, "det": "image_analysis"},
    {"kw": "qr code:", "id": "OCR-002", "sev": "HIGH", "conf": 0.95, "det": "image_analysis"},
    {"kw": "steganography:", "id": "OCR-003", "sev": "HIGH", "conf": 0.80, "det": "image_analysis"}
]


class ExplanationEngine:
    """Aggregates subscore outcomes and formats priority-sorted explainable summaries."""

    @classmethod
    def compile_explanation(
        self,
        prediction: str,
        risk_score: float,
        confidence: float,
        detector_outputs: dict[str, dict],
        fast_checks: dict
    ) -> ExplanationResponse:
        evidence_items: list[EvidenceItem] = []

        # 1. Parse Fast Checks
        fast_signals = fast_checks.get("signals", [])
        for sig in fast_signals:
            item = self._map_signal_to_evidence(sig, "fast_checks", fast_checks)
            if item:
                evidence_items.append(item)

        # 2. Parse Sub-Detectors
        for detector_name, out in detector_outputs.items():
            if not out:
                continue
            signals = out.get("signals", []) or out.get("evidence", [])
            metadata = out.get("metadata", {})
            for sig in signals:
                item = self._map_signal_to_evidence(sig, detector_name, metadata)
                if item:
                    evidence_items.append(item)

        # Remove duplicate evidence IDs to avoid clutter
        unique_evidence = {}
        for item in evidence_items:
            if item.id not in unique_evidence:
                unique_evidence[item.id] = item
            else:
                # Keep the one with higher severity/confidence
                existing = unique_evidence[item.id]
                if SEVERITY_ORDER.get(item.severity, 3) < SEVERITY_ORDER.get(existing.severity, 3):
                    unique_evidence[item.id] = item
        
        evidence_list = list(unique_evidence.values())

        # Sort: Critical first, then High, then Medium, then Low
        evidence_list.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 3))

        # 3. Determine high-level threat categories
        categories = classify_categories(evidence_list)

        # 4. Determine overall severity
        highest_severity = "LOW"
        if evidence_list:
            highest_severity = evidence_list[0].severity

        # 5. Formulate natural-language summary
        summary = self._generate_summary(prediction, categories, evidence_list)

        # 6. Generate tailored user/administrator recommendations
        recommendations = generate_recommendations(highest_severity)

        return ExplanationResponse(
            prediction=prediction.upper(),
            risk_score=risk_score,
            confidence=confidence,
            severity=highest_severity,
            category=categories,
            summary=summary,
            evidence=evidence_list,
            recommendation=recommendations
        )

    @classmethod
    def _map_signal_to_evidence(cls, signal: str, detector: str, metadata: dict) -> EvidenceItem | None:
        """Resolve a signal string to a structured EvidenceItem using pattern rules."""
        sig_lower = signal.lower()

        # Check mapping rules
        for rule in EVIDENCE_RULES:
            if rule["kw"] in sig_lower:
                # Compile supporting details
                details = {}
                if rule["id"] == "URL-003":
                    details["entropy"] = metadata.get("features", {}).get("entropy", 0.0)
                elif rule["id"] == "URL-002":
                    details["brand_similarity"] = metadata.get("features", {}).get("brand_similarity_score", 0.0)
                elif rule["id"] == "TI-001":
                    details["engines"] = metadata.get("virustotal_flags", 0)
                elif rule["id"] == "VIS-001":
                    details["phash_distance"] = metadata.get("best_hamming_distance", 999)
                elif rule["id"] == "VIS-002":
                    details["clip_similarity"] = metadata.get("clip_similarity", 0.0)
                elif rule["id"] == "OCR-002":
                    details["qr_urls"] = metadata.get("qr_urls", [])

                return EvidenceItem(
                    id=rule["id"],
                    detector=rule["det"],
                    severity=rule["sev"],
                    confidence=rule["conf"],
                    reason=signal,
                    details=details
                )

        # Fallback for unmapped fast checks (e.g. WHOIS/SSL)
        if detector == "fast_checks":
            e_id = "WHO-001"
            sev = "HIGH"
            if "ssl" in sig_lower or "certificate" in sig_lower:
                e_id = "SSL-001"
                sev = "MEDIUM"
            return EvidenceItem(
                id=e_id,
                detector="fast_checks",
                severity=sev,
                confidence=0.90,
                reason=signal,
                details={}
            )

        return None

    @classmethod
    def _generate_summary(cls, prediction: str, categories: list[str], evidence: list[EvidenceItem]) -> str:
        """Construct natural-language summary based on categorizations."""
        if prediction.upper() == "BENIGN":
            return "This website appears safe and does not display typical phishing patterns or reputation flags."

        if not categories:
            return "This website shows multiple suspicious technical signals suggesting a malicious campaign."

        # Formulate threat profile description
        impersonated_brand = None
        for item in evidence:
            if item.id in ("VIS-001", "VIS-002") and item.details.get("matched_brand") or "brand" in item.reason.lower():
                # Extract brand target
                words = item.reason.split()
                if "brand" in words:
                    idx = words.index("brand")
                    if idx + 1 < len(words):
                        impersonated_brand = words[idx+1].strip("'\"")
                break

        brand_str = f" impersonating {impersonated_brand}" if impersonated_brand else ""
        cats_str = " and ".join(categories[:2])

        return f"This website represents a high-risk threat ({cats_str}){brand_str} designed to target user assets."

    @classmethod
    def render_markdown(cls, exp: ExplanationResponse) -> str:
        """Render the ExplanationResponse as a human-friendly Markdown report."""
        lines = []
        lines.append(f"# Analysis Report: Risk Score {exp.risk_score}/100")
        lines.append("")
        lines.append(f"**Verdict**: {exp.prediction} ({exp.severity} Severity)")
        lines.append(f"**Confidence**: {exp.confidence*100:.1f}%")
        if exp.category:
            lines.append(f"**Categories**: {', '.join(exp.category)}")
        lines.append("")
        lines.append("## Summary")
        lines.append(exp.summary)
        lines.append("")
        lines.append("## Evidence Timeline")

        for item in exp.evidence:
            mitre = get_mitre_mapping(item.id)
            mitre_str = f" [MITRE {mitre['technique_id']}]" if mitre else ""
            lines.append(f"* **[{item.id}]** ({item.detector}): {item.reason}{mitre_str}")
            if item.details:
                detail_parts = [f"{k}={v}" for k, v in item.details.items()]
                lines.append(f"  * Supporting Values: `{', '.join(detail_parts)}`")

        lines.append("")
        lines.append("## Recommendations")
        lines.append(f"* **User**: {exp.recommendation.user}")
        lines.append(f"* **Administrator**: {exp.recommendation.administrator}")

        return "\n".join(lines)
