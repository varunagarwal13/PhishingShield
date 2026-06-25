import asyncio
import json
import unittest

import main
from feature_store import DomainFeatureStore
from model_registry import ModelRegistry
from observability import MetricsCollector


class FakeCache:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value, ex=None):
        self.values[key] = value


class ProductionArchitectureTests(unittest.TestCase):
    def test_model_registry_exposes_active_version(self):
        registry = ModelRegistry()
        metadata = registry.metadata()

        self.assertEqual(metadata["active_version"], "v2")
        self.assertIn("rf", metadata["artifacts"])
        self.assertIn("xgb", metadata["artifacts"])

    def test_feature_store_caches_domain_features(self):
        cache = FakeCache()
        store = DomainFeatureStore(cache)
        calls = {"count": 0}

        async def compute(domain):
            calls["count"] += 1
            return {"domain": domain, "ttl_hostname": 300}

        first = asyncio.run(store.get_or_compute("example.com", compute))
        second = asyncio.run(store.get_or_compute("example.com", compute))

        self.assertEqual(calls["count"], 1)
        self.assertFalse(first["feature_store_hit"])
        self.assertTrue(second["feature_store_hit"])
        self.assertEqual(second["ttl_hostname"], 300)

    def test_metrics_collector_renders_prometheus_text(self):
        metrics = MetricsCollector()
        metrics.increment("phishing_check_requests_total")
        metrics.increment("phishing_verdict_total", {"verdict": "ALLOW"})
        metrics.observe("phishing_check_latency", 0.25)
        output = metrics.render_prometheus()

        self.assertIn("phishing_check_requests_total 1", output)
        self.assertIn('phishing_verdict_total{verdict="ALLOW"} 1', output)
        self.assertIn("phishing_check_latency_seconds_count 1", output)

    def test_root_exposes_production_metadata(self):
        root = main.root()

        self.assertEqual(root["model_version"], "v2")
        self.assertIn(root["feature_store"], {"redis", "disabled"})

    def test_model_info_endpoint_returns_registry_metadata(self):
        info = main.model_info()

        self.assertEqual(info["active_version"], "v2")
        self.assertIn("feature_columns", info["artifacts"])

    def test_metrics_endpoint_returns_text_response(self):
        response = main.metrics_endpoint()

        self.assertEqual(response.media_type, "text/plain")
        self.assertIsInstance(response.body, bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
