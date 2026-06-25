import unittest

import main


class DomainPolicyTests(unittest.TestCase):
    def test_trusted_parent_domain_matches_subdomains(self):
        hostname = main.hostname_from_url("onlinesbi.sbi.bank.in")

        self.assertEqual(hostname, "onlinesbi.sbi.bank.in")
        self.assertTrue(main.is_trusted_hostname(hostname))

    def test_brand_keyword_on_untrusted_domain_is_not_whitelisted(self):
        hostname = main.hostname_from_url("secure-sbi-login.xyz")

        self.assertFalse(main.is_trusted_hostname(hostname))

    def test_brand_lookalike_domain_is_not_softened(self):
        hostname = main.hostname_from_url("login-microsoft-security.com")

        self.assertEqual(main.registered_domain_from_host(hostname), "login-microsoft-security.com")
        self.assertFalse(main.is_trusted_hostname(hostname))
        self.assertIsNone(main.trust_match_for_hostname(hostname))

        similarity = main.domain_similarity_check("login-microsoft-security.com")
        self.assertTrue(similarity["suspicious"])
        self.assertEqual(similarity["brand"], "microsoft")

    def test_short_brand_lookalike_is_detected(self):
        similarity = main.domain_similarity_check("sbl.co.in")

        self.assertTrue(similarity["suspicious"])
        self.assertEqual(similarity["brand"], "sbi")

    def test_trusted_text_inside_attacker_domain_is_not_trusted(self):
        hostname = main.hostname_from_url("sbi.bank.in.evil.com")

        self.assertEqual(main.registered_domain_from_host(hostname), "evil.com")
        self.assertFalse(main.is_trusted_hostname(hostname))
        self.assertIsNone(main.trust_match_for_hostname(hostname))

    def test_url_without_scheme_is_normalized(self):
        self.assertEqual(
            main.normalize_url("accounts.google.com"),
            "https://accounts.google.com",
        )
        self.assertEqual(
            main.hostname_from_url("https://www.google.com/login"),
            "google.com",
        )

    def test_tiered_verdict_thresholds(self):
        self.assertEqual(main.verdict_for_score(39.9)[0], "ALLOW")
        self.assertEqual(main.verdict_for_score(40)[0], "MONITOR")
        self.assertEqual(main.verdict_for_score(70)[0], "WARN")
        self.assertEqual(main.verdict_for_score(90)[0], "BLOCK")

    def test_trust_delta_is_bounded_and_conflict_aware(self):
        hostname = main.hostname_from_url("onlinesbi.sbi.bank.in")

        self.assertEqual(
            main.trusted_domain_delta(hostname, False, {"valid": True}),
            (-25.0, "onlinesbi.sbi.bank.in"),
        )
        self.assertEqual(
            main.trusted_domain_delta(hostname, False, {"valid": False}),
            (-10.0, "onlinesbi.sbi.bank.in"),
        )
        self.assertEqual(
            main.trusted_domain_delta(hostname, True, {"valid": True}),
            (0.0, "onlinesbi.sbi.bank.in"),
        )

    def test_arbitration_combines_calibrated_ml_rules_and_trust_delta(self):
        calibrated_ml = main.calibrate_ml_score(80.0, has_positive_rules=False)

        self.assertEqual(calibrated_ml, 40.0)
        self.assertEqual(main.arbitrate_score(calibrated_ml, 20.0, -25.0), 35.0)

    def test_positive_rule_score_is_bounded(self):
        self.assertEqual(main.bound_positive_rule_score(132.5), 75.0)

    def test_attack_pattern_classifier_detects_brand_lure(self):
        similarity = main.domain_similarity_check("login-microsoft-security.com/verify")
        attack = main.classify_attack_pattern(
            "login-microsoft-security.com/verify",
            {"qty_redirects": 0, "url_shortened": 0},
            {},
            {"is_typosquat": False},
            similarity,
            {},
            {},
        )

        self.assertIn("brand_impersonation", attack["patterns"])
        self.assertIn("credential_lure_url", attack["patterns"])
        self.assertGreaterEqual(attack["score"], 20.0)

    def test_lexical_feature_diagnostics_identify_dominant_features(self):
        diagnostics = main.diagnose_lexical_feature_risk(
            "https://secure-bank-login.example.com/account/verify",
            {"length_url": 88, "domain_length": 31, "qty_hyphen_domain": 2},
            {"subdomain_depth": 3, "keyword_count": 4},
        )

        self.assertIn("login", diagnostics["keyword_hits"])
        self.assertIn("deep_subdomain", diagnostics["risk_features"])
        self.assertIn("long_domain", diagnostics["risk_features"])
        self.assertIn("many_domain_hyphens", diagnostics["risk_features"])


if __name__ == "__main__":
    unittest.main()
