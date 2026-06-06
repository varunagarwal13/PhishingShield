from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
import joblib
import re
import json
import hashlib
import tldextract
import redis
import aiohttp
from urllib.parse import urlparse
from dotenv import load_dotenv
from database import init_db, get_db, ThreatLog, FeedbackLog
import os
import base64
from datetime import datetime

load_dotenv()
VT_API_KEY   = os.getenv("VT_API_KEY", "")
REDIS_URL    = os.getenv("REDIS_URL", "redis://127.0.0.1:6379")

app = FastAPI(title="Phishing Detector API v2")

@app.on_event("startup")
def startup():
    init_db()

print("Loading models...")
rf           = joblib.load("model_rf_v2.pkl")
xgb          = joblib.load("model_xgb_v2.pkl")
FEATURE_COLS = joblib.load("feature_cols_v2.pkl")
print(f"Models loaded. Features: {len(FEATURE_COLS)}")

# Redis — graceful fallback if not available
try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()
    print("Redis connected")
except:
    cache = None
    print("Redis not available — running without cache")

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
    "zoom.us","dropbox.com","onedrive.com"
}

RISKY_TLDS = {"tk","ml","ga","cf","gq","top","xyz","club","online","site",
              "work","party","live","click","link","win","loan","download"}

class URLRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    url: str
    feedback: str

def cache_key(url: str) -> str:
    return f"phish2:url:{hashlib.md5(url.encode()).hexdigest()}"

def extract_features(url: str) -> dict:
    try:
        parsed     = urlparse(url)
        ext        = tldextract.extract(url)
        domain     = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        path       = parsed.path or ""
        params     = parsed.query or ""
        path_parts = path.rsplit("/", 1)
        directory  = path_parts[0] if len(path_parts) > 1 else ""
        file_part  = path_parts[1] if len(path_parts) > 1 else ""

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
        features["qty_tld_url"]             = url.lower().count(ext.suffix) if ext.suffix else 0
        features["length_url"]              = len(url)
        features.update(char_counts(domain, "domain"))
        features["qty_vowels_domain"]       = sum(domain.count(v) for v in "aeiou")
        features["domain_length"]           = len(domain)
        features["domain_in_ip"]            = int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", ext.domain)))
        features["server_client_domain"]    = int("server" in domain or "client" in domain)
        features.update(char_counts(directory, "directory"))
        features["directory_length"]        = len(directory)
        features.update(char_counts(file_part, "file"))
        features["file_length"]             = len(file_part)
        features.update(char_counts(params, "params"))
        features["params_length"]           = len(params)
        features["tld_present_params"]      = int(ext.suffix in params if ext.suffix else False)
        features["qty_params"]              = len(params.split("&")) if params else 0
        features["email_in_url"]            = int("@" in url and "mailto" in url.lower())
        features["time_response"]           = -1
        features["domain_spf"]              = -1
        features["asn_ip"]                  = -1
        features["time_domain_activation"]  = -1
        features["time_domain_expiration"]  = -1
        features["qty_ip_resolved"]         = -1
        features["qty_nameservers"]         = -1
        features["qty_mx_servers"]          = -1
        features["ttl_hostname"]            = -1
        features["tls_ssl_certificate"]     = int(url.startswith("https"))
        features["qty_redirects"]           = 0
        features["url_google_index"]        = -1
        features["domain_google_index"]     = -1
        features["url_shortened"]           = int(ext.domain in [
            "bit","tinyurl","goo","ow","t","is","cli","yfrog","migre",
            "ff","url4","twit","su","snipurl","short","ping","post"
        ])
        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        return {col: -1 for col in FEATURE_COLS}

async def check_virustotal(url: str) -> dict:
    if not VT_API_KEY:
        return {"vt_malicious": 0, "vt_total": 0, "vt_checked": False}
    try:
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": VT_API_KEY}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    data  = await resp.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    return {
                        "vt_malicious": stats.get("malicious", 0),
                        "vt_total":     sum(stats.values()),
                        "vt_checked":   True
                    }
    except Exception as e:
        print(f"VT error: {e}")
    return {"vt_malicious": 0, "vt_total": 0, "vt_checked": False}

def get_signals(url: str, score: float, vt: dict) -> list:
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
    return signals[:3]

@app.get("/")
def root():
    return {
        "status":     "Phishing Detector API v2",
        "redis":      "connected" if cache else "disabled",
        "vt_enabled": bool(VT_API_KEY)
    }

@app.post("/check")
async def check_url(request: URLRequest, db: Session = Depends(get_db)):
    url = request.url.strip()
    key = cache_key(url)

    # 1. Redis cache
    try:
        cached = cache.get(key) if cache else None
        if cached:
            result = json.loads(cached)
            result["cached"] = True
            return result
    except Exception as e:
        print(f"Cache read error: {e}")

    # 2. Trusted domain whitelist
    ext               = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}"
    if registered_domain in TRUSTED_DOMAINS:
        result = {
            "url": url, "score": 0.0, "verdict": "ALLOW",
            "signals": [], "cached": False,
            "details": {"rf_score": 0.0, "xgb_score": 0.0,
                        "vt_malicious": 0, "vt_total": 0}
        }
        try:
            if cache: cache.set(key, json.dumps(result), ex=21600)
        except:
            pass
        return result

    # 3. ML scoring + VT
    features       = extract_features(url)
    feature_values = [[features.get(col, -1) for col in FEATURE_COLS]]
    rf_prob        = float(rf.predict_proba(feature_values)[0][1])
    xgb_prob       = float(xgb.predict_proba(feature_values)[0][1])
    ensemble_prob  = (rf_prob + xgb_prob) / 2
    vt             = await check_virustotal(url)

    ml_score = ensemble_prob * 100
    vt_boost = 0
    if vt["vt_checked"] and vt["vt_total"] > 0:
        vt_ratio = vt["vt_malicious"] / vt["vt_total"]
        vt_boost = vt_ratio * 30

    score   = min(round(ml_score + vt_boost, 1), 100.0)
    signals = get_signals(url, score, vt)

    if score >= 70:
        verdict = "BLOCK"
        ttl     = 86400
    elif score >= 40:
        verdict = "WARN"
        ttl     = 3600
    else:
        verdict = "ALLOW"
        ttl     = 3600

    # 4. Log to database
    try:
        log = ThreatLog(
            url          = url[:2048],
            score        = score,
            verdict      = verdict,
            signals      = json.dumps(signals),
            rf_score     = round(rf_prob * 100, 1),
            xgb_score    = round(xgb_prob * 100, 1),
            vt_malicious = vt["vt_malicious"],
            vt_total     = vt["vt_total"],
            cached       = 0,
            timestamp    = datetime.utcnow()
        )
        db.add(log)
        db.commit()
    except Exception as e:
        print(f"DB log error: {e}")

    result = {
        "url":     url,
        "score":   score,
        "verdict": verdict,
        "signals": signals,
        "cached":  False,
        "details": {
            "rf_score":     round(rf_prob * 100, 1),
            "xgb_score":    round(xgb_prob * 100, 1),
            "vt_malicious": vt["vt_malicious"],
            "vt_total":     vt["vt_total"],
            "vt_boost":     round(vt_boost, 1)
        }
    }

    try:
        if cache: cache.set(key, json.dumps(result), ex=ttl)
    except:
        pass

    return result

@app.post("/feedback")
def submit_feedback(request: FeedbackRequest, db: Session = Depends(get_db)):
    try:
        fb = FeedbackLog(
            url       = request.url[:2048],
            verdict   = "unknown",
            feedback  = request.feedback,
            timestamp = datetime.utcnow()
        )
        db.add(fb)
        db.commit()
        return {"status": "feedback recorded", "url": request.url, "feedback": request.feedback}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

@app.get("/logs")
def get_logs(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(ThreatLog).order_by(ThreatLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id":           l.id,
            "url":          l.url,
            "score":        l.score,
            "verdict":      l.verdict,
            "signals":      json.loads(l.signals or "[]"),
            "vt_malicious": l.vt_malicious,
            "timestamp":    str(l.timestamp)
        }
        for l in logs
    ]