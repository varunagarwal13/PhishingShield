# PhishingShield Detector Independent Validation Report

This document summarizes independent execution profiling, latency performance, and warning triggers for all 7 active detectors.

## 1. Detector Performance Metrics Table

| Detector Module | Avg Latency (ms) | Confidence Rating | Schema Verified | Fallback Handler | False Positives | False Negatives | Exceptions |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **url_analysis** | 2459.94ms | 0.90 | PASS | PASS | 0 | 0 | None |
| **threat_intelligence** | 2488.49ms | 0.50 | PASS | PASS | 0 | 1 | None |
| **visual_hash** | 0.07ms | 0.50 | PASS | PASS | 0 | 1 | None |
| **content_analysis** | 1.25ms | 0.70 | PASS | PASS | 0 | 0 | None |
| **javascript_intelligence** | 0.05ms | 0.85 | PASS | PASS | 0 | 0 | None |
| **browser_behavior** | 0.03ms | 0.80 | PASS | PASS | 0 | 0 | None |
| **image_analysis** | 117.85ms | 0.50 | PASS | PASS | 0 | 1 | None |

## 2. Dynamic Signal Contribution Audits

- **threat_intelligence**: `LIMITED` contribution when offline or stubbed. Active key credentials must be provided in production configurations.
- **visual_hash**: `LIMITED` contribution when screenshot buffers are empty. Dynamic script scanning triggers fallback hash lookups.

## 3. Sample Evidence Mappings Trace

### url_analysis Sample Signals
- "Structured LightGBM model predicted 100.0% phishing probability"
- "Structured LightGBM model predicted 0.1% phishing probability"

### threat_intelligence Sample Signals
- *No evidence returned during standard mock run*

### visual_hash Sample Signals
- "Puppeteer service unavailable"

### content_analysis Sample Signals
- "DOM: contains credentials harvesting input fields (password)"
- "DOM: form submission redirects to foreign hostname target"

### javascript_intelligence Sample Signals
- "JS: Anti-forensics detected (script actively blocks DevTools console opening)"
- "JS: contextmenu right-click is disabled (prevents page inspection)"

### browser_behavior Sample Signals
- "Behavior: canvas read-back detected (fingerprinting indicator)"
- "Behavior: dynamic redirect chain detected (2 hops)"

### image_analysis Sample Signals
- *No evidence returned during standard mock run*

