# PhishingShield Independent Audit: API Audit

This report details the audit of the PhishingShield API endpoints, routing schemas, input validation layers, and subsystem diagnostics.

---

## 1. Registered API Endpoints

The API router (`app/api/routes.py`) exposes the following endpoints with Pydantic validation:

* **Analysis Core**:
  * `POST /analyse` & `POST /api/v1/analyze`: Accepts `DetectionRequest` and returns `DetectionResponse`.
* **Subsystem Feedback**:
  * `POST /feedback`: Logs user bypasses or override updates to SQLite.
  * `POST /cache/clear`: Evicts Redis cache entries for a URL after overrides.
* **Orchestration Health**:
  * `GET /health` & `GET /api/v1/health`: Connection status checks for Redis and SQLite.
  * `GET /live` & `GET /api/v1/live`: Liveness checks.
  * `GET /ready` & `GET /api/v1/ready`: Readiness indicators validating model and pipeline loads.
* **Explainability Endpoints**:
  * `GET /analysis/explanation`: Returns full Pydantic-validated `ExplanationResponse`.
  * `GET /analysis/report`: Returns human-readable markdown summaries as a `PlainTextResponse`.
  * `GET /analysis/evidence`: Returns JSON list of raw evidence artifacts.

---

## 2. Input Security Validation Layer

* **URL length threshold**: Returns `400 Bad Request` if input exceeds `2048` characters.
* **Empty strings**: Intercepts empty or whitespace-only inputs.
* **Protocol check**: Validates that URLs use `http` or `https` schemes, rejecting FTP, data, or file schemes.
* **FastAPI Dependency Injection**: Pipelines are injected via `get_pipeline` to manage resources lifecycle per request.
