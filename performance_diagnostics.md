# PhishingShield Performance Diagnostics Report

## 1. Lazy Loading Latency Bottleneck

- **Analysis**: The 33 MB ensemble model pickle took ~2.4 seconds to load from disk during the first incoming URL request (cold-start).
- **Optimization**: Configured `main.py` lifespan startup script to pre-load `ModelLoader.get_structured_model()`. Subsequent analysis requests read from memory in < 1 ms.
