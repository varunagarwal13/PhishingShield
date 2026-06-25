import unittest

import main


class SecurityImprovementTests(unittest.TestCase):
    def test_trusted_suffix_must_match_registered_boundary(self):
        host = main.hostname_from_url("sbi.bank.in.evil.com")

        self.assertEqual(main.registered_domain_from_host(host), "evil.com")
        self.assertIsNone(main.trust_match_for_hostname(host))
        self.assertFalse(main.is_trusted_hostname(host))

    def test_trusted_domain_is_score_delta_not_allow_override(self):
        host = main.hostname_from_url("onlinesbi.sbi.bank.in")
        trust_delta, trusted_match = main.trusted_domain_delta(
            host,
            has_conflict=False,
            tls_validation={"valid": True},
        )

        self.assertEqual(trusted_match, "onlinesbi.sbi.bank.in")
        self.assertEqual(trust_delta, -25.0)
        self.assertEqual(main.arbitrate_score(55.0, 10.0, trust_delta), 40.0)

    def test_trust_delta_is_disabled_when_conflict_exists(self):
        host = main.hostname_from_url("onlinesbi.sbi.bank.in")
        trust_delta, trusted_match = main.trusted_domain_delta(
            host,
            has_conflict=True,
            tls_validation={"valid": True},
        )

        self.assertEqual(trusted_match, "onlinesbi.sbi.bank.in")
        self.assertEqual(trust_delta, 0.0)

    def test_microsoft_lookalike_is_flagged_but_not_trusted(self):
        host = main.hostname_from_url("login-microsoft-security.com")
        similarity = main.domain_similarity_check("login-microsoft-security.com/verify")

        self.assertIsNone(main.trust_match_for_hostname(host))
        self.assertTrue(similarity["suspicious"])
        self.assertEqual(similarity["brand"], "microsoft")

    def test_short_sbi_lookalike_is_detected(self):
        similarity = main.domain_similarity_check("sbl.co.in")

        self.assertTrue(similarity["suspicious"])
        self.assertEqual(similarity["brand"], "sbi")

    def test_attack_pattern_classifier_identifies_credential_lure(self):
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
        self.assertEqual(attack["classifier"], "deterministic_attack_pattern_v1")

    def test_lexical_diagnostics_show_dominant_features(self):
        diagnostics = main.diagnose_lexical_feature_risk(
            "https://secure-bank-login.example.com/account/verify",
            {"length_url": 88, "domain_length": 31, "qty_hyphen_domain": 2},
            {"subdomain_depth": 3, "keyword_count": 4},
        )

        self.assertIn("login", diagnostics["keyword_hits"])
        self.assertIn("suspicious_keywords", diagnostics["risk_features"])
        self.assertIn("deep_subdomain", diagnostics["risk_features"])
        self.assertIn("long_domain", diagnostics["risk_features"])
        self.assertIn("many_domain_hyphens", diagnostics["risk_features"])

    def test_rule_score_is_bounded_before_arbitration(self):
        self.assertEqual(main.bound_positive_rule_score(150.0), 75.0)
        self.assertEqual(main.arbitrate_score(40.0, 75.0, -10.0), 100.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
