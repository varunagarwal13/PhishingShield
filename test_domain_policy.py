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


if __name__ == "__main__":
    unittest.main()
