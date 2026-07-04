# PhishingShield Independent Audit: Dataset Audit

This report details the verification of the training, validation, and external benchmarking datasets used in PhishingShield.

---

## 1. Dataset Dimensions & Class Balance

* **Training Dataset size**: `130,280` URLs
* **Training Class Balance**: `65,140` Benign / `65,140` Malicious (exactly 1:1 balanced ratio)
* **Validation Dataset size**: `47,220` URLs
* **Missing or Corrupt Records**: `0` unparsable URLs detected in split pools.

---

## 2. Leakage Audits

* **URL Leakage Count**: `0` duplicate URL records found across Train and Test splits.
* **Domain Leakage Count**: `0` domains overlap between Train and Test splits.
* **Domain-Family Split**: `VERIFIED`. Splitting is performed strictly on registered domain level (`domain.tld`), guaranteeing zero test contamination from subdomains or directories.

---

## 3. Dataset Provenance & Licenses

* **PhishTank**: PhishTank Terms of Use / CC-BY-NC (`VERIFIED`)
* **URLHaus**: Creative Commons CC0 (Public Domain) (`VERIFIED`)
* **OpenPhish**: OpenPhish Free Feed Attribution (`VERIFIED`)
* **Tranco**: Creative Commons Attribution 4.0 International (`VERIFIED`)
* **CiscoUmbrella**: Cisco Umbrella Attribution License (`VERIFIED`)
