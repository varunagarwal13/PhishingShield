import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

from app.models.detection import DetectionRequest, Severity, DetectorResult
from app.detectors import DetectorContext
from app.services.cache import CacheService
from app.services.scoring import ScoringService
from app.utils.url_utils import UrlSecurityService
from app.pipeline.pipeline import DetectionPipeline
from app.database.connection import init_db
from app.ai.versioning import ModelRegistry

# Explainability Subsystem Imports
from app.ai.explainability.explanation_engine import ExplanationEngine
from app.ai.explainability.risk_taxonomy import classify_categories
from app.ai.explainability.mitre_mapping import get_mitre_mapping
from app.ai.explainability.recommendations import generate_recommendations
from app.ai.explainability.evidence import EvidenceItem


class PhishingShieldPipelineTests(unittest.TestCase):

    def setUp(self):
        init_db()

        self.url_security = UrlSecurityService()
        self.cache_service = CacheService()
        self.scoring_service = ScoringService()

        self.puppeteer_service = MagicMock()
        self.puppeteer_service.get_page_data = AsyncMock(return_value={
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
            "pageText": "Secure login, verify immediately your identity to avoid account lock."
        })

        self.pipeline = DetectionPipeline(
            url_security=self.url_security,
            cache_service=self.cache_service,
            puppeteer_service=self.puppeteer_service,
            scoring_service=self.scoring_service
        )

    def test_url_canonicalization(self):
        url = "http://GOOGLE.COM/path/../"
        canonical = self.url_security.canonicalize(url)
        self.assertEqual(canonical, "http://google.com/path/../")

    def test_model_registry_metadata(self):
        schema = ModelRegistry.get_feature_schema()
        if schema:
            self.assertIn("url_len", schema)
            self.assertIn("entropy", schema)

    def test_javascript_intelligence(self):
        from app.detectors.javascript_intelligence import JavaScriptIntelligenceDetector
        detector = JavaScriptIntelligenceDetector()
        context = DetectorContext(
            url="https://test.com", canonical_url="https://test.com",
            hostname="test.com", registered_domain="test.com",
            services={}, shared={"puppeteer_dom_signals": {"devtoolsBlocked": True, "rightClickDisabled": True}}
        )
        loop = asyncio.get_event_loop()
        res = loop.run_until_complete(detector.run(context))
        self.assertEqual(res.detector_name, "javascript_intelligence")
        self.assertGreater(res.score, 0.0)

    def test_browser_behavior(self):
        from app.detectors.browser_behavior import BrowserBehaviorDetector
        detector = BrowserBehaviorDetector()
        context = DetectorContext(
            url="https://test.com", canonical_url="https://test.com",
            hostname="test.com", registered_domain="test.com",
            services={}, shared={"puppeteer_dom_signals": {"redirectChain": ["a", "b"], "canvasFingerprinting": True}}
        )
        loop = asyncio.get_event_loop()
        res = loop.run_until_complete(detector.run(context))
        self.assertEqual(res.detector_name, "browser_behavior")
        self.assertGreater(res.score, 0.0)

    def test_scoring_verdicts(self):
        verdict = self.scoring_service._make_verdict(25, ["Some signal"], ["Some signal"])
        self.assertEqual(verdict["action"], "allow")
        verdict = self.scoring_service._make_verdict(55, ["Some warning"], ["Some warning"])
        self.assertEqual(verdict["action"], "warn")
        verdict = self.scoring_service._make_verdict(85, ["Critical threat"], ["Critical threat"])
        self.assertEqual(verdict["action"], "block")

    # ── Explainable AI Subsystem Unit Tests ──
    
    def test_explanation_engine_deterministic(self):
        # Run compiler twice with the same inputs and verify output remains identical
        outputs = {
            "url_analysis": {"score": 85.0, "signals": ["URL contains a raw IP address"], "metadata": {}, "confidence": 0.90},
            "threat_intelligence": {"score": 90.0, "signals": ["Google Safe Browsing: flagged as malicious"], "metadata": {}, "confidence": 1.0}
        }
        fast = {"signals": ["No WHOIS record found"], "partial_score": 15}

        exp1 = ExplanationEngine.compile_explanation("BLOCK", 90.0, 0.95, outputs, fast)
        exp2 = ExplanationEngine.compile_explanation("BLOCK", 90.0, 0.95, outputs, fast)

        self.assertEqual(exp1.summary, exp2.summary)
        self.assertEqual(len(exp1.evidence), len(exp2.evidence))
        for idx in range(len(exp1.evidence)):
            self.assertEqual(exp1.evidence[idx].id, exp2.evidence[idx].id)

    def test_explanation_engine_priority_order(self):
        # Verify Critical findings are prioritized and sorted at the top of the evidence list
        outputs = {
            "url_analysis": {"score": 20.0, "signals": ["High hostname character entropy"], "metadata": {}, "confidence": 0.80},
            "threat_intelligence": {"score": 95.0, "signals": ["Google Safe Browsing: flagged as malicious"], "metadata": {}, "confidence": 1.0}
        }
        fast = {"signals": ["URL utilizes a TLD flagged"], "partial_score": 15}

        exp = ExplanationEngine.compile_explanation("BLOCK", 95.0, 0.95, outputs, fast)
        
        # Google Safe Browsing mapped ID is TI-002 (CRITICAL)
        # Entropy mapped ID is URL-003 (MEDIUM)
        self.assertEqual(exp.evidence[0].id, "TI-002")
        self.assertEqual(exp.evidence[0].severity, "CRITICAL")
        self.assertEqual(exp.evidence[1].id, "URL-008")  # TLD (MEDIUM)
        self.assertEqual(exp.evidence[2].id, "URL-003")  # Entropy (MEDIUM)

    def test_explanation_engine_categories(self):
        # Verify category taxonomy maps indicators to Brand Impersonation and Credential Harvesting
        evidence = [
            EvidenceItem(id="VIS-001", detector="visual_hash", severity="CRITICAL", confidence=0.98, reason="Visual similarity is 98%"),
            EvidenceItem(id="DOM-001", detector="content_analysis", severity="HIGH", confidence=0.90, reason="Password fields present")
        ]
        categories = classify_categories(evidence)
        self.assertIn("Brand Impersonation", categories)
        self.assertIn("Credential Harvesting", categories)

    def test_explanation_engine_recommendations(self):
        # Verify recommendations are tailored based on severity levels
        rec_critical = generate_recommendations("CRITICAL")
        self.assertIn("Do not enter any credentials", rec_critical.user)
        self.assertIn("Block this domain", rec_critical.administrator)

        rec_medium = generate_recommendations("MEDIUM")
        self.assertIn("Verify the sender", rec_medium.user)
        self.assertIn("low-reputation monitor lists", rec_medium.administrator)

    def test_mitre_attack_mapping(self):
        # Verify MITRE techniques map correctly to obfuscation and evasion IDs
        m_obf = get_mitre_mapping("JS-004")
        self.assertEqual(m_obf["technique_id"], "T1027")

        m_evas = get_mitre_mapping("JS-003")
        self.assertEqual(m_evas["technique_id"], "T1622")

    def test_full_pipeline_mock_run(self):
        req = DetectionRequest(url="https://some-untrusted-site.com")
        self.pipeline.detectors["threat_intelligence"].analyze = MagicMock(
            return_value=DetectorResult(
                detector_name="threat_intelligence",
                score=0.0,
                confidence=0.5,
                execution_time=0.0,
                severity=Severity.info,
                evidence=[],
                metadata={"virustotal_flags": 0, "gsb_match": False, "phishtank_hit": False}
            )
        )
        loop = asyncio.get_event_loop()
        resp = loop.run_until_complete(self.pipeline.analyze(req))
        self.assertEqual(resp.url, "https://some-untrusted-site.com")
        self.assertIsInstance(resp.risk_score, float)


if __name__ == "__main__":
    unittest.main()

