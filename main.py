from fastapi import FastAPI, Depends
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
from urllib.parse import urlparse
from dotenv import load_dotenv
from database import init_db, get_db, ThreatLog, FeedbackLog
from bs4 import BeautifulSoup
import os
import base64
from datetime import datetime

load_dotenv()
VT_API_KEY  = os.getenv("VT_API_KEY", "")
GSB_API_KEY = os.getenv("GSB_API_KEY", "")
REDIS_URL   = os.getenv("REDIS_URL", "redis://127.0.0.1:6379")

app = FastAPI(title="Phishing Detector API v3")

@app.on_event("startup")
def startup():
    init_db()

print("Loading models...")
rf           = joblib.load("model_rf_v2.pkl")
xgb          = joblib.load("model_xgb_v2.pkl")
FEATURE_COLS = joblib.load("feature_cols_v2.pkl")
print(f"ML models loaded. Features: {len(FEATURE_COLS)}")

try:
    nlp_vectorizer = joblib.load("nlp_vectorizer.pkl")
    nlp_clf        = joblib.load("nlp_model.pkl")
    NLP_ENABLED    = True
    print("NLP model loaded.")
except:
    NLP_ENABLED = False
    print("NLP model not found.")

try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()
    print("Redis connected.")
except:
    cache = None
    print("Redis not available.")

TRUSTED_DOMAINS = {
    "github.com","google.com","microsoft.com","apple.com","amazon.com",
    "facebook.com","twitter.com","instagram.com","linkedin.com","youtube.com",
    "netflix.com","reddit.com","wikipedia.org","stackoverflow.com",
    "paypal.com","chase.com","wellsfargo.com","bankofamerica.com",
    "anthropic.com","openai.com","cloudflare.com","amazonaws.com",
    "docker.com","render.com","railway.app","vercel.com","netlify.com",
    "pypi.org","npmjs.com","medium.com","dev.to","gitlab.com",
    "bitbucket.org","heroku.com","digitalocean.com","stripe.com",
    "notion.so","figma.com","slack.com","zoom.us","dropbox.com","x.com",
    "flipkart.com","irctc.co.in","naukri.com","indianexpress.com"
}

RISKY_TLDS = {"tk","ml","ga","cf","gq","top","xyz","club","online","site",
              "work","party","live","click","link","win","loan","download"}

BRAND_NAMES_LEV = [
    "paypal","google","amazon","facebook","netflix","apple","microsoft",
    "sbi","hdfc","icici","paytm","instagram","twitter","linkedin",
    "chase","wellsfargo","bankofamerica","dropbox","github","steam"
]

class URLRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    url: str
    feedback: str

def cache_key(url: str) -> str:
    return f"phish3:url:{hashlib.md5(url.encode()).hexdigest()}"

def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1!=c2)))
        prev = curr
    return prev[-1]

def check_typosquatting(url: str) -> dict:
    ext     = tldextract.extract(url)
    domain  = ext.domain.lower()
    if len(domain) < 4:
        return {"is_typosquat": False, "closest_brand": None, "distance": 99}
    min_dist = min(levenshtein(domain, brand) for brand in BRAND_NAMES_LEV)
    closest  = min(BRAND_NAMES_LEV, key=lambda b: levenshtein(domain, b))
    is_typo  = 0 < min_dist <= 2
    return {"is_typosquat": is_typo, "closest_brand": closest, "distance": min_dist}

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

async def fetch_page_text(url: str) -> str:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=4),
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                ssl=False
            ) as resp:
                if resp.status != 200:
                    return ""
                html = await resp.text()
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup(["script","style","meta","link"]):
                    tag.decompose()
                text = soup.get_text(separator=" ", strip=True)
                return text[:3000]
    except:
        return ""

def nlp_score(text: str) -> float:
    if not NLP_ENABLED or not text:
        return 0.0
    try:
        vec  = nlp_vectorizer.transform([text])
        return float(nlp_clf.predict_proba(vec)[0][1])
    except:
        return 0.0

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
                elif resp.status == 404:
                    # Submit URL to VT for future scanning
                    try:
                        async with session.post(
                            "https://www.virustotal.com/api/v3/urls",
                            headers=headers,
                            data={"url": url},
                            timeout=aiohttp.ClientTimeout(total=3)
                        ) as _:
                            pass
                    except:
                        pass
    except Exception as e:
        print(f"VT error: {e}")
    return {"vt_malicious": 0, "vt_total": 0, "vt_checked": False}

async def check_google_safe_browsing(url: str) -> dict:
    if not GSB_API_KEY:
        return {"gsb_match": False, "threat_type": None}
    try:
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=4)
            ) as resp:
                if resp.status == 200:
                    data    = await resp.json()
                    matches = data.get("matches", [])
                    if matches:
                        return {
                            "gsb_match":   True,
                            "threat_type": matches[0].get("threatType", "UNKNOWN")
                        }
        return {"gsb_match": False, "threat_type": None}
    except Exception as e:
        print(f"GSB error: {e}")
        return {"gsb_match": False, "threat_type": None}

async def check_phash(url: str) -> dict:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://127.0.0.1:8001/check",
                json={"url": url},
                timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
    except:
        pass
    return {"is_clone": False, "brand": None, "distance": None}

def get_signals(url, score, vt, nlp_prob, phash, gsb, typo) -> list:
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
    if gsb.get("gsb_match"):
        signals.append(f"Google Safe Browsing: {gsb.get('threat_type','threat')} detected")
    if nlp_prob > 0.7:
        signals.append("Urgent/suspicious page content detected")
    if phash.get("is_clone") and phash.get("brand"):
        signals.append(f"Visual clone of {phash['brand'].upper()} detected")
    if typo.get("is_typosquat"):
        signals.append(f"Typosquatting: resembles {typo['closest_brand']} (distance {typo['distance']})")
    return signals[:3]

@app.get("/")
def root():
    return {
        "status":      "Phishing Detector API v3",
        "redis":       "connected" if cache else "disabled",
        "vt_enabled":  bool(VT_API_KEY),
        "gsb_enabled": bool(GSB_API_KEY),
        "nlp_enabled": NLP_ENABLED
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
            "details": {
                "rf_score": 0.0, "xgb_score": 0.0,
                "vt_malicious": 0, "vt_total": 0,
                "nlp_score": 0.0, "nlp_boost": 0.0,
                "phash_clone": False, "phash_brand": None, "phash_boost": 0.0,
                "gsb_match": False, "gsb_threat": None,
                "typosquat": False, "typo_boost": 0.0
            }
        }
        try:
            if cache: cache.set(key, json.dumps(result), ex=21600)
        except:
            pass
        return result

    # 3. ML scoring
    features       = extract_features(url)
    feature_values = [[features.get(col, -1) for col in FEATURE_COLS]]
    rf_prob        = float(rf.predict_proba(feature_values)[0][1])
    xgb_prob       = float(xgb.predict_proba(feature_values)[0][1])
    ensemble_prob  = (rf_prob + xgb_prob) / 2

    # 4. Run all checks in parallel
    vt, page_text, phash_result, gsb = await asyncio.gather(
        check_virustotal(url),
        fetch_page_text(url),
        check_phash(url),
        check_google_safe_browsing(url)
    )
    nlp_prob = nlp_score(page_text)
    typo     = check_typosquatting(url)

    # 5. Combine scores
    ml_score    = ensemble_prob * 100
    vt_boost    = 0.0
    nlp_boost   = 0.0
    phash_boost = 0.0
    gsb_boost   = 0.0
    typo_boost  = 0.0

    if vt["vt_checked"] and vt["vt_total"] > 0:
        vt_boost = (vt["vt_malicious"] / vt["vt_total"]) * 30

    if nlp_prob > 0.7:
        nlp_boost = (nlp_prob - 0.7) * 20

    if phash_result.get("is_clone") and phash_result.get("brand"):
        phash_boost = 40.0

    if gsb.get("gsb_match"):
        gsb_boost = 40.0

    if typo.get("is_typosquat"):
        typo_boost = 25.0

    score   = min(round(ml_score + vt_boost + nlp_boost + phash_boost + gsb_boost + typo_boost, 1), 100.0)
    signals = get_signals(url, score, vt, nlp_prob, phash_result, gsb, typo)

    if score >= 70:
        verdict = "BLOCK"
        ttl     = 86400
    elif score >= 40:
        verdict = "WARN"
        ttl     = 3600
    else:
        verdict = "ALLOW"
        ttl     = 3600

    # 6. Log to database
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
            "vt_boost":     round(vt_boost, 1),
            "nlp_score":    round(nlp_prob * 100, 1),
            "nlp_boost":    round(nlp_boost, 1),
            "phash_clone":  bool(phash_result.get("is_clone", False)),
            "phash_brand":  phash_result.get("brand"),
            "phash_boost":  phash_boost,
            "gsb_match":    gsb.get("gsb_match", False),
            "gsb_threat":   gsb.get("threat_type"),
            "gsb_boost":    gsb_boost,
            "typosquat":    typo.get("is_typosquat", False),
            "typo_brand":   typo.get("closest_brand"),
            "typo_boost":   typo_boost
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
        return {"status": "feedback recorded"}
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