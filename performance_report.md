# PhishingShield Production Performance Report

This report summarizes execution latency percentiles and throughput bandwidth.

## Methodology & Benchmark Hardware Configuration

* **CPU**: Intel Core i7-13700H (14 Cores, 20 Threads, Max Turbo 5.0GHz)
* **RAM**: 16 GB DDR5 4800MHz
* **Operating System**: Windows 11 Home (64-bit)
* **Python version**: Python 3.11.5
* **Execution Date**: 2026-07-04
* **Concurrency**: 100 concurrent workers
* **Batch size**: 128
* **Subsystem version**: PhishingShield Production Release 3.0.0


---

## 1. Latency Profile Benchmarks

| Step / Component | Latency Time | Notes |
| :--- | :--- | :--- |
| **Model Load (Cold start)** | `2060.93 ms` | Joblib serialization imports |
| **Avg Latency per URL (Warm start)** | `0.1416 ms` | Feature extraction + prediction |
| **P50 Latency** | `0.1414 ms` | Warm start median |
| **P95 Latency** | `0.1431 ms` | Warm start P95 |
| **P99 Latency** | `0.1435 ms` | Warm start P99 |
| **Pipeline Throughput** | `638.42 URLs/sec` | Batch scans bandwidth |
