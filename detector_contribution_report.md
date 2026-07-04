# PhishingShield Detector Contribution Report

## 1. Relative Sub-Detector Influence

| Detector | Weight | Avg Contribution | Impact Severity | Status |
| :--- | :--- | :--- | :--- | :--- |
| **url_analysis** | 0.20 | 20.0% | HIGH | Active |
| **threat_intelligence** | 0.25 | 10.0% | MEDIUM | Credentials Required |
| **visual_hash** | 0.15 | 15.0% | HIGH | Active |
| **content_analysis** | 0.15 | 15.0% | HIGH | Active |
| **javascript_intelligence** | 0.10 | 10.0% | MEDIUM | Active |
| **browser_behavior** | 0.08 | 8.0% | MEDIUM | Active |
| **image_analysis** | 0.07 | 7.0% | LOW | Active |

## 2. Ignored Outputs
- Detectors with status `no_screenshot_available` are ignored to prevent zero-score scaling dilution.
