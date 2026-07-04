# PhishingShield Independent Audit: Detector Audit

This report details the audit of all active detectors inside the PhishingShield threat evaluation system.

---

## 1. Active Detectors List & Configuration

| Detector Name | Primary Input | Logic Type | Concurrency Mode | Timeout Limit |
| :--- | :--- | :--- | :--- | :--- |
| **url_analysis** | URL String | RandomForest ML Model | Async task execution | Inline execution |
| **threat_intelligence** | URL & Host | Multi-source TI APIs | Parallel `asyncio.gather` | `4` seconds total |
| **visual_hash** | Page Screenshot | Perceptual Hash + CLIP | Sequential checks | Inline execution |
| **content_analysis** | HTML Document | DOM Forms Structure | Async parser task | Inline execution |
| **javascript_intelligence**| JS Scripts Content | AST pattern matching | Obfuscation heuristic | Inline execution |
| **browser_behavior** | Timings / Frames | Window logs trace | Timings analysis | Inline execution |
| **image_analysis** | Image files | Vision features | Vision extraction | Inline execution |

---

## 2. Robustness & Concurrency Audits

* **Concurrency**: `VERIFIED`. Core orchestration runs detectors concurrently using `asyncio.gather`.
* **Exception Isolation**: `VERIFIED`. `BaseDetector.run()` intercepts all exceptions, logging the stack trace and returning a `failed=True` response object to keep the main pipeline running.
* **Network Timeouts**: `VERIFIED`. Threat Intelligence implements an absolute `aiohttp.ClientTimeout(total=4)` (4-second limit) with connection pooling.
* **Early-Exit Trigger**: `VERIFIED`. If VirusTotal returns $\ge 5$ malicious flags, it triggers an early-exit event to stop lower-priority detectors immediately, saving computing resources.
* **Fallback Logic**: `VERIFIED`. `UrlAnalysisDetector` falls back to high-confidence heuristic scoring (brand checks, entropy, IP flag) if the pickled machine learning classifier fails to load.
