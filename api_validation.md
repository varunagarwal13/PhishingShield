# PhishingShield FastAPI Endpoints Validation Report

This document summarizes liveness checks, malformed URL validations, input schema exceptions, and OpenAPI compliance.

## 1. Endpoints Validation Results Table

| Test Group | Route / Target Case | Status Code | Latency (ms) | Schema Verified | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Endpoint Reachability | `GET /live (Liveness status)` | 200 | 9.83ms | PASS | PASS |
| Endpoint Reachability | `GET /api/v1/live (Versioned liveness)` | 200 | 4.12ms | PASS | PASS |
| Endpoint Reachability | `GET /health (Health diagnosis)` | 200 | 9.01ms | PASS | PASS |
| Endpoint Reachability | `GET /ready (Subsystem readiness)` | 200 | 3.57ms | PASS | PASS |
| Endpoint Reachability | `POST /analyse (URL Analysis)` | 200 | 38.45ms | PASS | PASS |
| Endpoint Reachability | `POST /feedback (User Feedback)` | 200 | 23.59ms | PASS | PASS |
| Endpoint Reachability | `POST /cache/clear (Cache Clear)` | 200 | 4.94ms | PASS | PASS |
| Endpoint Reachability | `GET /analysis/explanation?url=https://google.com (Explainability details)` | 200 | 5.92ms | PASS | PASS |
| Endpoint Reachability | `GET /analysis/report?url=https://google.com (Markdown rendering)` | 200 | 6.13ms | PASS | PASS |
| Endpoint Reachability | `GET /analysis/evidence?url=https://google.com (Raw evidence check)` | 200 | 7.87ms | PASS | PASS |
| Fuzzing Checks | `Invalid URL Scheme (FTP)` | 400 | 3.91ms | PASS | PASS |
| Fuzzing Checks | `Empty URL payload` | 400 | 3.65ms | PASS | PASS |
| Fuzzing Checks | `Malformed URL String` | 400 | 4.25ms | PASS | PASS |
| Fuzzing Checks | `Extremely Long URL (>2048 chars)` | 400 | 3.28ms | PASS | PASS |
| Fuzzing Checks | `Unicode Domain Path` | 200 | 10462.95ms | PASS | PASS |
| Fuzzing Checks | `Missing payload fields` | 422 | 9.13ms | PASS | PASS |
| Fuzzing Checks | `Malformed request JSON syntax` | 422 | 7.92ms | PASS | PASS |
| OpenAPI Documentation | `GET /openapi.json` | 200 | 45.18ms | PASS | PASS |

## 2. OpenAPI Schema Consistency Statement

The schema endpoint returned a status of `200`. Verification: `PASS`. All routes registered inside the APIRouter are matched dynamically in the schema definition structure.
