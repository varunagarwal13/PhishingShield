# Classifier Modernization Architecture

## Overview

The project now supports a modular production architecture while preserving the original FastAPI endpoints. The legacy `/check`, `/logs`, `/feedback`, `/health`, and `/metrics` routes remain available. The new versioned pipeline is exposed at `/api/v1/analyze` with detector-level evidence and weighted risk aggregation.

## Component Diagram

```mermaid
flowchart LR
    Client["API Client"] --> Middleware["Request Context Middleware"]
    Middleware --> Routes["FastAPI Routes"]
    Routes --> Pipeline["DetectionPipeline"]
    Pipeline --> Aggregator["RiskAggregator"]
    Pipeline --> Explanation["ExplanationBuilder"]
    Pipeline --> ML["MLDetector"]
    Pipeline --> Heuristic["HeuristicDetector"]
    Pipeline --> Reputation["ReputationDetector"]
    Pipeline --> HTML["HtmlDetector"]
    Pipeline --> DNS["DNSDetector"]
    Pipeline --> SSL["SSLDetector"]
    Pipeline --> WHOIS["WhoisDetector"]
    Pipeline --> OCR["OCRDetector"]
    Pipeline --> Favicon["FaviconDetector"]
    Reputation --> VT["VirusTotalService"]
    HTML --> HtmlService["HtmlService"]
    ML --> FeatureService["FeatureService"]
    Routes --> DB["ThreatLogRepository"]
```

## Detection Sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant P as DetectionPipeline
    participant D as Detectors
    participant R as RiskAggregator
    C->>A: POST /api/v1/analyze
    A->>P: DetectionRequest
    P->>P: Canonicalize URL and build context
    P->>D: Run enabled detectors with asyncio.gather
    D-->>P: DetectorResult list
    P->>D: Run lazy OCR if required
    P->>R: Weighted aggregation
    R-->>P: Final risk score and verdict
    P-->>A: DetectionResponse with explanations
    A-->>C: JSON response
```

## Production Features

- Modular `app/` package with `api`, `config`, `detectors`, `pipeline`, `services`, `schemas`, `database`, and `models`.
- Detector plugin contract: `analyze()`, `explain()`, and `health_check()`.
- Parallel detector execution with failure isolation.
- Weighted risk aggregation with configurable detector weights.
- Explainable AI response reasons from detector evidence.
- URL canonicalization, punycode conversion, percent-decoding, homograph skeletons, SSRF private-host guard, and dynamic trusted-domain reload.
- Model integrity verification hook for SHA256 and version metadata.
- JSON logging formatter, Prometheus text metrics endpoint, health/readiness/liveness endpoints, request IDs, and correlation IDs.
- Optional threat-intelligence adapter classes for Google Safe Browsing, OpenPhish, PhishTank, URLHaus, AbuseIPDB, and Cloudflare Radar.

