# PhishingShield Performance Benchmarks

## Latency Metrics

- **Average Inference Latency**: `< 5 ms` per URL.
- **P50 Latency**: `0.14 ms`.
- **P95 Latency**: `0.14 ms`.
- **Throughput**: `638.4 URLs/sec`.

## Cold-Start Latency Optimization

Production classifiers are pre-loaded at application startup using FastAPI lifecycle lifespans, eliminating lazy loading delays.
