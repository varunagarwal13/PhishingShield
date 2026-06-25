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

    def test_legitimate_infrastructure_domains_are_not_brand_spoofs(self):
        urls = [
            "https://update.googleapis.com",
            "https://office365.com",
            "https://outlook.office365.com",
            "https://pki.goog",
            "https://lh3.googleusercontent.com",
            "https://dns.msftncsi.com",
            "https://gateway.fe2.apple-dns.net",
            "https://ep2.adtrafficquality.google",
            "https://appsflyersdk.com",
            "https://global.aa-rt.sharepoint.com",
            "https://tpc.googlesyndication.com",
            "https://public.onecdn.static.microsoft",
            "https://google.fastly-edge.com",
            "https://static.cloudflareinsights.com",
            "https://edge-consumer-static.azureedge.net",
            "https://www.google-analytics.com",
        ]

        for url in urls:
            with self.subTest(url=url):
                host = main.hostname_from_url(url)
                self.assertTrue(main.is_legitimate_infrastructure_hostname(host))
                self.assertFalse(main.domain_similarity_check(url)["suspicious"])

    def test_short_unrelated_domain_is_not_typosquatting_sbi(self):
        typo = main.check_typosquatting("https://pki.goog")

        self.assertFalse(typo["is_typosquat"])
        self.assertEqual(typo["closest_brand"], "sbi")

    def test_digit_heavy_random_domain_is_not_homoglyph_attack_without_brand_similarity(self):
        attack = main.classify_attack_pattern(
            "https://7kc7orgms5ahc.io/docs",
            {"qty_redirects": 0, "url_shortened": 0},
            {"has_homoglyph": 1, "has_unicode": 0},
            {"is_typosquat": False},
            {"suspicious": False},
            {},
            {},
        )

        self.assertNotIn("brand_impersonation", attack["patterns"])
        self.assertNotIn("homoglyph_spoofing", attack["patterns"])

    def test_infrastructure_delta_is_stronger_when_no_conflict(self):
        delta, match = main.infrastructure_domain_delta("update.googleapis.com", False)

        self.assertEqual(match, "googleapis.com")
        self.assertEqual(delta, -45.0)

    def test_low_conflict_trusted_domain_is_capped_to_monitor(self):
        score, cap = main.apply_low_conflict_domain_cap(
            91.0,
            "hdfcbank.com",
            None,
            trust_conflict=False,
            infrastructure_conflict=False,
        )

        self.assertEqual(score, 65.0)
        self.assertEqual(cap, 65.0)

    def test_low_conflict_cap_does_not_apply_when_trust_conflict_exists(self):
        score, cap = main.apply_low_conflict_domain_cap(
            91.0,
            "hdfcbank.com",
            None,
            trust_conflict=True,
            infrastructure_conflict=False,
        )

        self.assertEqual(score, 91.0)
        self.assertIsNone(cap)

    def test_legitimate_infrastructure_cloud_signal_is_suppressed_without_hard_conflict(self):
        attack = main.classify_attack_pattern(
            "https://lh3.googleusercontent.com",
            {"qty_redirects": 0, "url_shortened": 0},
            {"is_cloud_hosted": 1, "cloud_suspicious": 1},
            {"is_typosquat": False},
            {"suspicious": False},
            {},
            {},
        )

        self.assertNotIn("cloud_hosted_phishing", attack["patterns"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
