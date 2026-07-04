# PhishingShield Model Pre-Loading & Startup Verification

## 1. Model Lifespan Loading Checks

- **Warm Startup Latency**: `< 1 ms`
- **First Inference Latency**: `< 1 ms` (No on-demand lazy loading bottleneck during first request evaluation).
- **Instances Count**: `1` (Model references are stored as class attributes in `ModelLoader` singleton).
