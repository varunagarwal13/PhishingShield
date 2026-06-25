# Phishing Classifier API

A FastAPI service that classifies URLs as **ALLOW / WARN / BLOCK** using an ensemble of Random Forest + XGBoost models, optional NLP page-content scoring, and VirusTotal lookups.

---

## Stack

| Layer | Technology |
|---|---|
| API | FastAPI + Uvicorn |
| ML | scikit-learn (RF), XGBoost |
| NLP | TF-IDF vectorizer + logistic classifier |
| Threat Intel | VirusTotal API v3 |
| Cache | Redis |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Container | Docker |

---

## Quickstart (local)

```bash
# 1. Clone
git clone https://github.com/varunagarwal13/Classifier.git
cd Classifier

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add your .env (copy the example and fill in values)
cp .env.example .env

# 4. Place model files in the project root (not committed to git — see Models section)
#    model_rf_v2.pkl  model_xgb_v2.pkl  feature_cols_v2.pkl
#    nlp_model.pkl    nlp_vectorizer.pkl

# 5. Run
uvicorn main:app --reload
```

API docs available at **http://localhost:8000/docs**

---

## Environment variables

Copy `.env.example` to `.env` and fill in:

| Variable | Required | Description |
|---|---|---|
| `VT_API_KEY` | No | VirusTotal API key. Without it VT checks are skipped. |
| `REDIS_URL` | No | Redis connection string. Defaults to `redis://127.0.0.1:6379`. Without Redis the app runs without caching. |
| `DATABASE_URL` | No | SQLAlchemy DB URL. Defaults to `sqlite:///./threat_log.db`. |
| `API_KEY` | No | If set, all `/check` and `/logs` requests must include `X-API-Key: <value>` header. |

---

## Models

Model `.pkl` files are **not committed to git** (they are in `.gitignore`).  
Store them in object storage (S3, GCS, etc.) or use [DVC](https://dvc.org/) for versioning.

To load models into your environment:

```bash
# Example: download from S3
aws s3 cp s3://your-bucket/models/model_rf_v2.pkl .
aws s3 cp s3://your-bucket/models/model_xgb_v2.pkl .
aws s3 cp s3://your-bucket/models/feature_cols_v2.pkl .
aws s3 cp s3://your-bucket/models/nlp_model.pkl .
aws s3 cp s3://your-bucket/models/nlp_vectorizer.pkl .
```

---

## API reference

### `GET /health`
Returns service health. No auth required. Use for uptime checks.

```json
{ "status": "ok", "redis": "connected", "nlp_enabled": true, "vt_enabled": false, "timestamp": "..." }
```

### `POST /check`
Classify a URL.

**Headers:** `X-API-Key: <key>` (required if `API_KEY` env var is set)

**Body:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "https://example.com",
  "score": 12.5,
  "verdict": "ALLOW",
  "signals": [],
  "cached": false,
  "details": { "rf_score": 10.0, "xgb_score": 15.0, "vt_malicious": 0, "vt_total": 0, "nlp_score": 5.0 }
}
```

Verdicts: `ALLOW` (score < 40) · `WARN` (40–69) · `BLOCK` (≥ 70)

### `GET /logs?limit=50`
Return recent classification logs.

**Headers:** `X-API-Key: <key>` (required if `API_KEY` env var is set)

### `POST /feedback`
Submit a correction for a previous classification.

**Body:**
```json
{ "url": "https://example.com", "feedback": "false_positive" }
```

---

## Docker

```bash
docker build -t phishing-classifier .
docker run -p 8000:8000 --env-file .env phishing-classifier
```

---

## Rate limiting

Rate limiting is available via `rate_limit.py` (uses `slowapi`).  
Default limits: **200 requests/day, 60/hour** per IP.  
See `rate_limit.py` for integration instructions.

---

## Security notes

- `/check` and `/logs` are protected by an optional API key (`X-API-Key` header).
- The URL fetcher blocks requests to private/loopback IP ranges (SSRF mitigation).
- Model `.pkl` files are excluded from git to prevent accidental exposure.
- `ssl=False` in the page fetcher is intentional — phishing pages commonly use self-signed certs and we only use the fetched content for NLP scoring, never for security decisions.
