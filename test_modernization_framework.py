import asyncio
import tempfile
import unittest
from pathlib import Path

from app.detectors.base_detector import BaseDetector, DetectorContext
from app.pipeline.aggregator import RiskAggregator
from app.pipeline.pipeline import DetectionPipeline
from app.schemas.detection import DetectionRequest, DetectorResult, Severity
from app.services.url_security import UrlSecurityService


class FailingDetector(BaseDetector):
    name = "failing"

    async def analyze(self, context):
        raise RuntimeError("boom")


class StaticDetector(BaseDetector):
    name = "heuristic"

    async def analyze(self, context):
        return DetectorResult(
            detector_name=self.name,
            score=80.0,
            confidence=1.0,
            execution_time=0.0,
            severity=Severity.high,
            evidence=["static risk"],
            metadata={},
        )


class ModernizationFrameworkTests(unittest.TestCase):
    def test_url_security_canonicalizes_and_detects_homograph(self):
        service = UrlSecurityService()
        canonical = service.canonicalize("HTTP://googl%D0%B5.com./login")

        self.assertEqual(canonical, "http://xn--googl-3we.com/login")
        self.assertEqual(service.hostname("google.com"), "google.com")
        self.assertTrue(service.homograph_matches("g00gle.com") or service.skeleton("g00gle.com") == "google.com")

    def test_trusted_domains_reload_from_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trusted_domains.json"
            path.write_text('{"domains": ["example.test"]}', encoding="utf-8")
            service = UrlSecurityService(path)

            self.assertTrue(service.is_trusted("login.example.test"))

            path.write_text('{"domains": ["updated.test"]}', encoding="utf-8")
            service.reload_trusted_domains()

            self.assertFalse(service.is_trusted("login.example.test"))
            self.assertTrue(service.is_trusted("api.updated.test"))

    def test_detector_failures_do_not_fail_pipeline(self):
        service = UrlSecurityService()
        pipeline = DetectionPipeline(
            url_security=service,
            services={},
            aggregator=RiskAggregator({"heuristic": 1.0, "failing": 1.0}),
            enabled_detectors=[],
        )
        pipeline.detectors = [StaticDetector(), FailingDetector()]

        response = asyncio.run(pipeline.analyze(DetectionRequest(url="example.com")))

        self.assertEqual(response.verdict, "WARN")
        self.assertTrue(any(result.failed for result in response.detector_results))
        self.assertIn("static risk", response.reasons)

    def test_detector_result_contract_contains_required_fields(self):
        context = DetectorContext(
            url="example.com",
            canonical_url="https://example.com",
            hostname="example.com",
            registered_domain="example.com",
        )
        result = asyncio.run(StaticDetector().run(context))

        self.assertEqual(result.detector_name, "heuristic")
        self.assertGreaterEqual(result.execution_time, 0.0)
        self.assertEqual(result.severity, Severity.high)


if __name__ == "__main__":
    unittest.main()

