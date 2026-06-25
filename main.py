from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.security.api_key import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from sqlalchemy.orm import Session
import joblib
import re
import json
import hashlib
import asyncio
import tldextract
import redis
import aiohttp
import logging
import ipaddress
from urllib.parse import urlparse
from dotenv import load_dotenv
from database import init_db, get_db, ThreatLog, FeedbackLog
from bs4 import BeautifulSoup
import os
import base64
from datetime import datetime, timezone

load_dotenv()

# --- Logging (Fix #7: replace print with logging) ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# --- Config ---
VT_API_KEY = os.getenv("VT_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379")
API_KEY = os.getenv("API_KEY", "")  # Fix #3: protect /logs and /check

TRUSTED_DOMAINS = {
    "github.com","google.com","microsoft.com","apple.com","amazon.com",
    "facebook.com","twitter.com","instagram.com","linkedin.com","youtube.com",
    "netflix.com","reddit.com","wikipedia.org","stackoverflow.com",
    "paypal.com","chase.com","wellsfargo.com","bankofamerica.com",
    "anthropic.com","openai.com","cloudflare.com","amazonaws.com",
    "docker.com","render.com","railway.app","vercel.com","netlify.com",
    "pypi.org","npmjs.com","medium.com","dev.to","gitlab.com",
    "bitbucket.org","heroku.com","digitalocean.com","linode.com",
    "stripe.com","twilio.com","sendgrid.com","mongodb.com","firebase.com",
    "notion.so","figma.com","canva.com","trello.com","slack.com",
    "zoom.us","dropbox.com","onedrive.com","x.com"
}

RISKY_TLDS = {"tk","ml","ga","cf","gq","top","xyz","club","online","site",
              "work","party","live","click","link","win","loan","download"}

# Fix #11: Rate limiter — 30 requests/minute per IP on /check
limiter = Limiter(key_func=get_remote_address, default_limits=["200/day", "60/hour"])

# Fix #3: API key header scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str = Depends(api_key_header)):
    if API_KEY and key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


# Fix #1 + #8: lifespan replaces deprecated @app.on_event("startup")
# Models stored on app.state — accessible from any route, no module-level globals
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Loading models...")
    app.state.rf = joblib.load("model_rf_v2.pkl")
    app.state.xgb = joblib.load("model_xgb_v2.pkl")
    app.state.FEATURE_COLS = joblib.load("feature_cols_v2.pkl")
    logger.info(f"ML models loaded. Features: {len(app.state.FEATURE_COLS)}")

    try:
        app.state.nlp_vectorizer = joblib.load("nlp_vectorizer.pkl")
        app.state.nlp_clf = joblib.load("nlp_model.pkl")
        app.state.NLP_ENABLED = True
        logger.info("NLP model loaded.")
    except FileNotFoundError:
        app.state.NLP_ENABLED = False
        logger.warning("NLP model not found — skipping.")
    except Exception as e:
        app.state.NLP_ENABLED = False
        logger.warning(f"NLP model failed to load: {e}")

    try:
        cache = redis.from_url(REDIS_URL, decode_responses=True)
        cache.ping()
        app.state.cache = cache
        logger.info("Redis connected.")
    except redis.RedisError as e:
        app.state.cache = None
        logger.warning(f"Redis not available — running without cache. ({e})")

    yield

    logger.info("Shutting down.")


app = FastAPI(title="Phishing Detector API v2", lifespan=lifespan)

# Fix #11: attach limiter and its exception handler to the app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# --- Request models ---
class URLRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    url: str
    feedback: str


# --- Helpers ---
def cache_key(url: str) -> str:
    # MD5 used only as a non-cryptographic cache key
    return f"phish2:url:{hashlib.md5(url.encode()).hexdigest()}"


# Fix #2: URL input validation — raises HTTP 400 on bad input instead of crashing
def validate_url(url: str):
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL exceeds maximum length of 2048 characters.")
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"URL could not be parsed: {e}")
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only http and https URLs are supported.")
    if not parsed.netloc or parsed.netloc.strip() == "":
        raise HTTPException(status_code=400, detail="URL has no valid domain.")
    ext = tldextract.extract(url)
    if not ext.domain:
        raise HTTPException(status_code=400, detail="URL has no recognisable domain.")


# Fix #4: SSRF guard — block private/loopback IPs before fetching page content
def is_private_host(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return True
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        # hostname is a domain name, not an IP — allow it through
        return False


def extract_features(url: str, feature_cols: list) -> dict:
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        path = parsed.path or ""
        params = parsed.query or ""
        path_parts = path.rsplit("/", 1)
        directory = path_parts[0] if len(path_parts) > 1 else ""
        file_part = path_parts[1] if len(path_parts) > 1 else ""

        def char_counts(s, prefix):
            chars = {
                "dot":".", "hyphen":"-", "underline":"_", "slash":"/",
                "questionmark":"?", "equal":"=", "at":"@", "and":"&",
                "exclamation":"!", "space":" ", "tilde":"~", "comma":",",
                "plus":"+", "asterisk":"*", "hashtag":"#", "dollar":"$",
                "percent":"%"
            }
            return {f"qty_{name}_{prefix}": s.count(c) for name, c in chars.items()}

        features = {}
        features.update(char_counts(url, "url"))
        features["qty_tld_url"] = url.lower().count(ext.suffix) if ext.suffix else 0
        features["length_url"] = len(url)
        features.update(char_counts(domain, "domain"))
        features["qty_vowels_domain"] = sum(domain.count(v) for v in "aeiou")
        features["domain_length"] = len(domain)
        features["domain_in_ip"] = int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", ext.domain)))
        features["server_client_domain"] = int("server" in domain or "client" in domain)
        features.update(char_counts(directory, "directory"))
        features["directory_length"] = len(directory)
        features.update(char_counts(file_part, "file"))
        features["file_length"] = len(file_part)
        features.update(char_counts(params, "params"))
        features["params_length"] = len(params)
        features["tld_present_params"] = int(ext.suffix in params if ext.suffix else False)
        features["qty_params"] = len(params.split("&")) if params else 0
        features["email_in_url"] = int("@" in url and "mailto" in url.lower())
        features["time_response"] = -1
        features["domain_spf"] = -1
        features["asn_ip"] = -1
        features["time_domain_activation"] = -1
        features["time_domain_expiration"] = -1
        features["qty_ip_resolved"] = -1
        features["qty_nameservers"] = -1
        features["qty_mx_servers"] = -1
        features["ttl_hostname"] = -1
        features["tls_ssl_certificate"] = int(url.startswith("https"))
        features["qty_redirects"] = 0
        features["url_google_index"] = -1
        features["domain_google_index"] = -1
        features["url_shortened"] = int(ext.domain in [
            "bit","tinyurl","goo","ow","t","is","cli","yfrog","migre",
            "ff","url4","twit","su","snipurl","short","ping","post"
        ])
        return features
    except Exception as e:
        logger.error(f"Feature extraction error for url={url!r}: {e}")
        return {col: -1 for col in feature_cols}


# Fix #4: ssl=False intentional — phishing pages often have bad/self-signed certs.
# Page text is only used for NLP scoring, never for security decisions.
# SSRF mitigated by is_private_host() called before this function.
async def fetch_page_text(url: str) -> str:
    if is_private_host(url):
        logger.warning(f"Blocked fetch to private/loopback host: {url}")
        return ""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=4),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                ssl=False
            ) as resp:
                html = await resp.text()
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup(["script","style","meta","link"]):
                    tag.decompose()
                text = soup.get_text(separator=" ", strip=True)
                return text[:3000]
    except aiohttp.ClientError as e:
        logger.warning(f"Page fetch network error for {url}: {e}")
        return ""
    except Exception as e:
        logger.warning(f"Page fetch failed for {url}: {e}")
        return ""


def nlp_score(text: str, app_state) -> float:
    if not app_state.NLP_ENABLED or not text:
        return 0.0
    try:
        vec = app_state.nlp_vectorizer.transform([text])
        return float(app_state.nlp_clf.predict_proba(vec)[0][1])
    except Exception as e:
        logger.error(f"NLP scoring error: {e}")
        return 0.0


async def check_virustotal(url: str) -> dict:
    if not VT_API_KEY:
        return {"vt_malicious": 0, "vt_total": 0, "vt_checked": False}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": VT_API_KEY}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    return {
                        "vt_malicious": stats.get("malicious", 0),
                        "vt_total": sum(stats.values()),
                        "vt_checked": True
                    }
    except aiohttp.ClientError as e:
        logger.error(f"VirusTotal network error: {e}")
    except (KeyError, ValueError) as e:
        logger.error(f"VirusTotal response parse error: {e}")
    except Exception as e:
        logger.error(f"VirusTotal unexpected error: {e}")
    return {"vt_malicious": 0, "vt_total": 0, "vt_checked": False}


def get_signals(url: str, score: float, vt: dict, nlp_prob: float) -> list:
    signals = []
    ext = tldextract.extract(url)
    if ext.suffix and ext.suffix.split(".")[-1] in RISKY_TLDS:
        signals.append("Suspicious TLD")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ext.domain):
        signals.append("IP address as domain")
    if any(w in url.lower() for w in ["verify","secure","confirm","credential","suspend"]):
        signals.append("Suspicious keywords in URL")
    if any(b in ext.domain.lower() for b in ["paypal","microsoft","apple","amazon","google"]):
        signals.append("Brand name in unknown domain")
    if "@" in url:
        signals.append("@ symbol in URL")
    if not url.startswith("https"):
        signals.append("No HTTPS")
    if vt["vt_checked"] and vt["vt_malicious"] > 0:
        signals.append(f"VirusTotal: {vt['vt_malicious']}/{vt['vt_total']} engines flagged")
    if nlp_prob > 0.7:
        signals.append("Urgent/suspicious page content detected")
    return signals


# --- Routes ---

# Fix #9: /health endpoint for ops/uptime monitoring
@app.get("/health")
def health(request: Request):
    return {
        "status": "ok",
        "redis": "connected" if request.app.state.cache else "disabled",
        "nlp_enabled": request.app.state.NLP_ENABLED,
        "vt_enabled": bool(VT_API_KEY),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/")
def root(request: Request):
    return {
        "status": "Phishing Detector API v2",
        "redis": "connected" if request.app.state.cache else "disabled",
        "vt_enabled": bool(VT_API_KEY),
        "nlp_enabled": request.app.state.NLP_ENABLED
    }


# Fix #3: /check protected by API key (enforced only when API_KEY env var is set)
# Fix #11: rate limited to 30 requests/minute per IP
@app.post("/check")
@limiter.limit("30/minute")
async def check_url(
    url_request: URLRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: str = Depends(require_api_key),
):
    s = request.app.state

    # Fix #2: validate before doing anything else
    url = url_request.url.strip()
    validate_url(url)

    key = cache_key(url)

    # 1. Redis cache
    try:
        cached = s.cache.get(key) if s.cache else None
        if cached:
            result = json.loads(cached)
            result["cached"] = True
            return result
    except redis.RedisError as e:
        logger.warning(f"Cache read error: {e}")

    # 2. Trusted domain whitelist
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}"
    if registered_domain in TRUSTED_DOMAINS:
        result = {
            "url": url, "score": 0.0, "verdict": "ALLOW",
            "signals": [], "cached": False,
            "details": {"rf_score": 0.0, "xgb_score": 0.0,
                        "vt_malicious": 0, "vt_total": 0,
                        "nlp_score": 0.0, "nlp_boost": 0.0}
        }
        try:
            if s.cache:
                s.cache.set(key, json.dumps(result), ex=21600)
        except redis.RedisError as e:
            logger.warning(f"Cache write error: {e}")
        return result

    # 3. ML + VT + NLP in parallel
    features = extract_features(url, s.FEATURE_COLS)
    feature_values = [[features.get(col, -1) for col in s.FEATURE_COLS]]

    rf_prob = float(s.rf.predict_proba(feature_values)[0][1])
    xgb_prob = float(s.xgb.predict_proba(feature_values)[0][1])
    ensemble_prob = (rf_prob + xgb_prob) / 2

    vt, page_text = await asyncio.gather(
        check_virustotal(url),
        fetch_page_text(url)
    )

    nlp_prob = nlp_score(page_text, s)

    ml_score = ensemble_prob * 100
    vt_boost = 0.0
    nlp_boost = 0.0

    if vt["vt_checked"] and vt["vt_total"] > 0:
        vt_ratio = vt["vt_malicious"] / vt["vt_total"]
        vt_boost = vt_ratio * 30

    if nlp_prob > 0.7:
        nlp_boost = (nlp_prob - 0.7) * 20

    score = min(round(ml_score + vt_boost + nlp_boost, 1), 100.0)
    signals = get_signals(url, score, vt, nlp_prob)

    if score >= 70:
        verdict = "BLOCK"
        ttl = 86400
    elif score >= 40:
        verdict = "WARN"
        ttl = 3600
    else:
        verdict = "ALLOW"
        ttl = 3600

    # 4. Log to database
    try:
        log = ThreatLog(
            url=url[:2048],
            score=score,
            verdict=verdict,
            signals=json.dumps(signals),
            rf_score=round(rf_prob * 100, 1),
            xgb_score=round(xgb_prob * 100, 1),
            vt_malicious=vt["vt_malicious"],
            vt_total=vt["vt_total"],
            cached=0,
            timestamp=datetime.now(timezone.utc)
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.error(f"DB log error: {e}")
        db.rollback()

    result = {
        "url": url,
        "score": score,
        "verdict": verdict,
        "signals": signals,
        "cached": False,
        "details": {
            "rf_score": round(rf_prob * 100, 1),
            "xgb_score": round(xgb_prob * 100, 1),
            "vt_malicious": vt["vt_malicious"],
            "vt_total": vt["vt_total"],
            "vt_boost": round(vt_boost, 1),
            "nlp_score": round(nlp_prob * 100, 1),
            "nlp_boost": round(nlp_boost, 1)
        }
    }

    try:
        if s.cache:
            s.cache.set(key, json.dumps(result), ex=ttl)
    except redis.RedisError as e:
        logger.warning(f"Cache write error: {e}")

    return result


@app.post("/feedback")
def submit_feedback(request: FeedbackRequest, db: Session = Depends(get_db)):
    try:
        fb = FeedbackLog(
            url=request.url[:2048],
            verdict="unknown",
            feedback=request.feedback,
            timestamp=datetime.now(timezone.utc)
        )
        db.add(fb)
        db.commit()
        return {"status": "feedback recorded", "url": request.url, "feedback": request.feedback}
    except Exception as e:
        logger.error(f"Feedback log error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Could not record feedback.")


# Fix #3: /logs protected by API key
@app.get("/logs", dependencies=[Depends(require_api_key)])
def get_logs(limit: int = 50, db: Session = Depends(get_db)):
    try:
        logs = db.query(ThreatLog).order_by(ThreatLog.timestamp.desc()).limit(limit).all()
        return [
            {
                "id": l.id,
                "url": l.url,
                "score": l.score,
                "verdict": l.verdict,
                "signals": json.loads(l.signals or "[]"),
                "vt_malicious": l.vt_malicious,
                "timestamp": str(l.timestamp)
            }
            for l in logs
        ]
    except Exception as e:
        logger.error(f"Logs fetch error: {e}")
        raise HTTPException(status_code=500, detail="Could not fetch logs.")