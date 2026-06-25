from fastapi import FastAPI, Depends, Response
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
import socket
import ssl
import time
from urllib.parse import urlparse
from dotenv import load_dotenv
from database import init_db, get_db, ThreatLog, FeedbackLog
from bs4 import BeautifulSoup
import os
import base64
from datetime import datetime
from extract_advanced_features import extract_advanced_features
from fast_check import fast_definitive_check
from runtime_features import get_runtime_domain_features
from image_scan import run_image_scan
from dom_check import check_dom_signals
from feature_store import DomainFeatureStore
from model_registry import ModelRegistry
from observability import MetricsCollector

load_dotenv()
VT_API_KEY  = os.getenv("VT_API_KEY", "")
GSB_API_KEY = os.getenv("GSB_API_KEY", "")
REDIS_URL   = os.getenv("REDIS_URL", "redis://127.0.0.1:6379")

app = FastAPI(title="Phishing Detector API v8")
TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
metrics = MetricsCollector()

@app.on_event("startup")
def startup():
    init_db()

print("Loading models...")
model_registry = ModelRegistry()
rf, xgb, FEATURE_COLS = model_registry.load_core_models()
print(f"ML models loaded. Version: {model_registry.active_version}. Features: {len(FEATURE_COLS)}")

nlp_vectorizer, nlp_clf, NLP_ENABLED = model_registry.load_nlp_models()
print("NLP model loaded." if NLP_ENABLED else "NLP model not found.")

try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()
    print("Redis connected.")
except:
    cache = None
    print("Redis not available.")

feature_store = DomainFeatureStore(cache)

def load_trusted_domains():
    domains = {
        "github.com","google.com","microsoft.com","apple.com","amazon.com",
        "facebook.com","twitter.com","instagram.com","linkedin.com","youtube.com",
        "netflix.com","reddit.com","wikipedia.org","stackoverflow.com",
        "paypal.com","chase.com","wellsfargo.com","bankofamerica.com",
        "anthropic.com","openai.com","cloudflare.com","amazonaws.com",
        "docker.com","render.com","railway.app","vercel.com","netlify.com",
        "pypi.org","npmjs.com","medium.com","dev.to","gitlab.com",
        "bitbucket.org","heroku.com","digitalocean.com","stripe.com",
        "notion.so","figma.com","slack.com","zoom.us","dropbox.com","x.com",
        "flipkart.com","irctc.co.in","naukri.com","indianexpress.com",
        "sbi.bank.in","onlinesbi.sbi.bank.in","retail.sbi.bank.in",
        "hdfcbank.com","icicibank.com","axisbank.com","kotak.com",
        "paytm.com","microsoftonline.com"
    }
    print(f"Loaded {len(domains)} curated trusted domains")
    return domains

TRUSTED_DOMAINS = load_trusted_domains()

CLOUD_SUBDOMAINS = {
    # Google
    "sites.google.com", "docs.google.com", "drive.google.com",
    "googleusercontent.com",
    # Firebase/Cloudflare
    "web.app", "firebaseapp.com", "pages.dev", "workers.dev",
    # GitHub
    "github.io",
    # Netlify/Vercel
    "netlify.app", "vercel.app",
    # Framer/Webflow/Glitch
    "framer.app", "webflow.io", "glitch.me",
    # Website builders
    "weebly.com", "wixsite.com", "godaddysites.com",
    "squarespace.com", "cargo.site", "typedream.app",
    # Hosting
    "sharepoint.com", "host.secureserver.net",
    "myftpupload.com", "clients.dts.su",
    # Blogging platforms
    "blogspot.com", "wordpress.com",
}

RISKY_TLDS = {"tk","ml","ga","cf","gq","top","xyz","club","online","site",
              "work","party","live","click","link","win","loan","download"}

BRAND_NAMES_LEV = [
    "paypal","google","amazon","facebook","netflix","apple","microsoft",
    "sbi","hdfc","icici","paytm","instagram","twitter","linkedin",
    "chase","wellsfargo","bankofamerica","dropbox","github","steam"
]

SUSPICIOUS_URL_TERMS = {
    "login", "verify", "secure", "account", "update", "confirm", "banking",
    "password", "credential", "suspended", "unlock", "reactivate", "billing",
    "signin", "wallet", "validate", "kyc"
}

class URLRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    url: str
    feedback: str

def cache_key(url: str) -> str:
    return f"phish8:url:{hashlib.md5(url.encode()).hexdigest()}"

def domain_cache_key(domain: str) -> str:
    return f"phish8:domain:{hashlib.md5(domain.encode()).hexdigest()}"

def negative_cache_key(url: str) -> str:
    return f"phish8:neg:{hashlib.md5(url.encode()).hexdigest()}"

def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        return f"https://{url}"
    return url

def hostname_from_url(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname

def registered_domain_from_host(hostname: str) -> str:
    ext = TLD_EXTRACTOR(hostname)
    if not ext.suffix:
        return ext.domain.lower()
    return f"{ext.domain}.{ext.suffix}".lower()

def host_matches_domain(hostname: str, trusted_domain: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    trusted_domain = trusted_domain.lower().rstrip(".")
    return hostname == trusted_domain or hostname.endswith(f".{trusted_domain}")

def trust_match_for_hostname(hostname: str) -> str | None:
    hostname = hostname.lower().rstrip(".")
    hostname_registered_domain = registered_domain_from_host(hostname)
    for trusted_domain in sorted(TRUSTED_DOMAINS, key=len, reverse=True):
        trusted_domain = trusted_domain.lower().rstrip(".")
        if (host_matches_domain(hostname, trusted_domain) and
                hostname_registered_domain == registered_domain_from_host(trusted_domain)):
            return trusted_domain
    return None

def is_trusted_hostname(hostname: str) -> bool:
    return trust_match_for_hostname(hostname) is not None

def is_cloud_hostname(hostname: str) -> bool:
    return any(host_matches_domain(hostname, cloud_domain) for cloud_domain in CLOUD_SUBDOMAINS)

def verdict_for_score(score: float) -> tuple[str, int]:
    if score >= 90:
        return "BLOCK", 86400
    if score >= 70:
        return "WARN", 3600
    if score >= 40:
        return "MONITOR", 3600
    return "ALLOW", 3600

def clamp_score(score: float) -> float:
    return min(max(round(score, 1), 0.0), 100.0)

def calibrate_ml_score(ml_score: float, has_positive_rules: bool) -> float:
    if not has_positive_rules and ml_score < 85:
        return ml_score * 0.5
    return ml_score

def has_trust_conflict(vt, gsb, typo, adv, phash, dom, image,
                       domain_similarity=None, attack_patterns=None) -> bool:
    domain_similarity = domain_similarity or {}
    attack_patterns = attack_patterns or {}
    return (
        (vt.get("vt_checked") and vt.get("vt_malicious", 0) > 0) or
        bool(gsb.get("gsb_match")) or
        bool(typo.get("is_typosquat")) or
        bool(domain_similarity.get("suspicious")) or
        bool(attack_patterns.get("patterns")) or
        bool(phash.get("is_clone") and phash.get("brand")) or
        bool(adv.get("has_homoglyph")) or
        bool(adv.get("is_cloud_hosted") and adv.get("cloud_suspicious")) or
        bool(adv.get("has_ip_in_domain")) or
        bool(image.get("qr_url_flagged")) or
        bool(dom.get("has_login_form") and dom.get("form_action_mismatch"))
    )

async def validate_tls_certificate(hostname: str) -> dict:
    if not hostname:
        return {"checked": False, "valid": False, "issuer": None, "error": "missing hostname"}
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _validate_tls_certificate, hostname), timeout=4.0
        )
    except Exception as e:
        return {"checked": False, "valid": False, "issuer": None, "error": str(e)}

def _validate_tls_certificate(hostname: str) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
    issuer = None
    issuer_parts = cert.get("issuer", ())
    for group in issuer_parts:
        for key, value in group:
            if key == "organizationName":
                issuer = value
                break
        if issuer:
            break
    return {"checked": True, "valid": True, "issuer": issuer, "error": None}

def trusted_domain_delta(
    hostname: str,
    has_conflict: bool,
    tls_validation: dict | None = None,
    scheme: str = "https",
) -> tuple[float, str | None]:
    trusted_match = trust_match_for_hostname(hostname)
    if not trusted_match or has_conflict or scheme != "https":
        return 0.0, trusted_match
    if tls_validation and tls_validation.get("valid"):
        return -25.0, trusted_match
    return -10.0, trusted_match

def arbitrate_score(ml_score: float, positive_rule_score: float, trust_delta: float) -> float:
    return clamp_score(ml_score + positive_rule_score + trust_delta)

def bound_positive_rule_score(score: float) -> float:
    return min(round(score, 1), 75.0)

def diagnose_lexical_feature_risk(url: str, features: dict, adv: dict) -> dict:
    url_lower = normalize_url(url).lower()
    keyword_hits = sorted(term for term in SUSPICIOUS_URL_TERMS if term in url_lower)
    risky = []

    if keyword_hits:
        risky.append("suspicious_keywords")
    if adv.get("subdomain_depth", 0) >= 3:
        risky.append("deep_subdomain")
    if features.get("length_url", 0) >= 90:
        risky.append("long_url")
    if features.get("domain_length", 0) >= 28:
        risky.append("long_domain")
    if features.get("qty_hyphen_domain", 0) >= 2:
        risky.append("many_domain_hyphens")
    if adv.get("keyword_count", 0) >= 2:
        risky.append("keyword_density")

    return {
        "keyword_hits": keyword_hits,
        "subdomain_depth": adv.get("subdomain_depth", 0),
        "url_length": features.get("length_url", 0),
        "domain_length": features.get("domain_length", 0),
        "domain_hyphens": features.get("qty_hyphen_domain", 0),
        "keyword_count": adv.get("keyword_count", 0),
        "risk_features": risky,
    }

def classify_attack_pattern(url: str, features: dict, adv: dict, typo: dict,
                            domain_similarity: dict, dom: dict, phash: dict) -> dict:
    patterns = []

    if domain_similarity.get("suspicious") or typo.get("is_typosquat") or adv.get("has_homoglyph"):
        patterns.append("brand_impersonation")
    if adv.get("has_unicode") or adv.get("has_homoglyph"):
        patterns.append("homoglyph_spoofing")
    if adv.get("is_cloud_hosted") and adv.get("cloud_suspicious"):
        patterns.append("cloud_hosted_phishing")
    if adv.get("has_ip_in_domain"):
        patterns.append("ip_obfuscation")
    if dom.get("has_login_form") and dom.get("form_action_mismatch"):
        patterns.append("credential_harvesting")
    if phash.get("is_clone") and phash.get("brand"):
        patterns.append("visual_brand_clone")

    url_lower = normalize_url(url).lower()
    credential_terms = {"login", "signin", "password", "credential", "account"}
    verification_terms = {"verify", "confirm", "update", "secure", "unlock", "reactivate", "kyc"}
    if any(t in url_lower for t in credential_terms) and any(t in url_lower for t in verification_terms):
        patterns.append("credential_lure_url")

    if features.get("qty_redirects", 0) >= 2 or features.get("url_shortened", 0):
        patterns.append("redirect_abuse")

    unique_patterns = sorted(set(patterns))
    score = min(len(unique_patterns) * 12.0, 35.0)
    severe = any(p in unique_patterns for p in [
        "credential_harvesting", "visual_brand_clone", "brand_impersonation", "homoglyph_spoofing"
    ])
    if severe:
        score = max(score, 20.0)

    return {
        "patterns": unique_patterns,
        "score": score,
        "classifier": "deterministic_attack_pattern_v1",
    }

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

def normalize_brand_text(value: str) -> str:
    replacements = {
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
        "6": "g", "7": "t", "8": "b", "@": "a", "!": "i",
    }
    normalized = value.lower()
    for fake, real in replacements.items():
        normalized = normalized.replace(fake, real)
    return re.sub(r"[^a-z0-9]", "", normalized)

def char_ngrams(value: str, size: int = 2) -> set[str]:
    if len(value) <= size:
        return {value}
    return {value[i:i + size] for i in range(len(value) - size + 1)}

def ngram_similarity(left: str, right: str) -> float:
    left_grams = char_ngrams(left)
    right_grams = char_ngrams(right)
    if not left_grams or not right_grams:
        return 0.0
    return len(left_grams & right_grams) / len(left_grams | right_grams)

def domain_similarity_check(url: str) -> dict:
    ext = TLD_EXTRACTOR(normalize_url(url))
    hostname = hostname_from_url(url)
    domain = ext.domain.lower()
    normalized_domain = normalize_brand_text(domain)
    trusted_match = trust_match_for_hostname(hostname)

    best = {
        "suspicious": False,
        "brand": None,
        "reason": None,
        "distance": 99,
        "similarity": 0.0,
        "boost": 0.0,
    }
    if trusted_match or len(normalized_domain) < 3:
        return best

    domain_tokens = [t for t in re.split(r"[^a-z0-9]+", domain) if t]
    for brand in BRAND_NAMES_LEV:
        normalized_brand = normalize_brand_text(brand)
        distance = levenshtein(normalized_domain, normalized_brand)
        similarity = ngram_similarity(normalized_domain, normalized_brand)
        reason = None

        if brand in domain_tokens or brand in normalized_domain:
            reason = "brand term in untrusted domain"
        elif distance <= 1:
            reason = "near brand edit distance"
        elif len(normalized_brand) >= 5 and distance <= 2 and similarity >= 0.45:
            reason = "brand lookalike edit distance"
        elif similarity >= 0.72:
            reason = "brand ngram similarity"

        if reason:
            boost = 30.0 if distance <= 1 else 25.0
            if boost > best["boost"]:
                best = {
                    "suspicious": True,
                    "brand": brand,
                    "reason": reason,
                    "distance": distance,
                    "similarity": round(similarity, 3),
                    "boost": boost,
                }

    return best

def check_typosquatting(url: str) -> dict:
    ext     = TLD_EXTRACTOR(normalize_url(url))
    domain  = ext.domain.lower()
    if len(domain) < 3:
        return {"is_typosquat": False, "closest_brand": None, "distance": 99}
    min_dist = min(levenshtein(domain, brand) for brand in BRAND_NAMES_LEV)
    closest  = min(BRAND_NAMES_LEV, key=lambda b: levenshtein(domain, b))
    is_typo  = 0 < min_dist <= 2
    return {"is_typosquat": is_typo, "closest_brand": closest, "distance": min_dist}

def extract_features(url: str) -> dict:
    try:
        url        = normalize_url(url)
        parsed     = urlparse(url)
        ext        = TLD_EXTRACTOR(url)
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
        features["tls_ssl_certificate"]     = int(parsed.scheme == "https")
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
        url = normalize_url(url)
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

async def check_virustotal(url: str, stop_event: asyncio.Event = None) -> dict:
    if not VT_API_KEY:
        return {"vt_malicious": 0, "vt_total": 0, "vt_checked": False}
    try:
        url = normalize_url(url)
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": VT_API_KEY}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    data      = await resp.json()
                    stats     = data["data"]["attributes"]["last_analysis_stats"]
                    malicious = stats.get("malicious", 0)
                    if malicious >= 5 and stop_event is not None:
                        stop_event.set()
                    return {
                        "vt_malicious": malicious,
                        "vt_total":     sum(stats.values()),
                        "vt_checked":   True
                    }
                elif resp.status == 404:
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
        url = normalize_url(url)
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
        url = normalize_url(url)
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

def get_signals(url, score, vt, nlp_prob, phash, gsb, typo, adv=None, fast=None,
                img=None, dom=None, domain_similarity=None, attack_patterns=None) -> list:
    adv  = adv or {}
    fast = fast or {}
    img  = img or {}
    dom  = dom or {}
    domain_similarity = domain_similarity or {}
    attack_patterns = attack_patterns or {}
    signals = []
    ext = TLD_EXTRACTOR(normalize_url(url))
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
    if urlparse(normalize_url(url)).scheme != "https":
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
    if domain_similarity.get("suspicious"):
        signals.append(
            f"Brand lookalike: resembles {domain_similarity.get('brand')} "
            f"({domain_similarity.get('reason')})"
        )
    if attack_patterns.get("patterns"):
        signals.append(f"Attack pattern: {attack_patterns['patterns'][0].replace('_', ' ')}")
    if adv.get("has_unicode"):
        signals.append("Unicode/Cyrillic homoglyph domain detected")
    elif adv.get("has_homoglyph"):
        signals.append("Character substitution homoglyph detected")
    if adv.get("is_cloud_hosted") and adv.get("cloud_suspicious"):
        signals.append("Suspicious content hosted on cloud platform")
    if adv.get("is_high_entropy"):
        signals.append("High domain randomness (AI-generated pattern)")
    if adv.get("has_ip_in_domain"):
        signals.append("Raw IP address embedded in domain/subdomain")
    for s in fast.get("signals", []):
        signals.append(s)
    if img.get("qr_url_flagged"):
        signals.append("Suspicious URL embedded in QR code")
    if img.get("ocr_suspicious"):
        signals.append("Urgency language detected in page image (OCR)")
    if img.get("steganography_detected"):
        signals.append("Possible hidden data in image (steganography)")
    if dom.get("form_action_mismatch"):
        signals.append(f"Login form submits to different domain: {dom.get('form_action_domain')}")
    if dom.get("hidden_iframe_count", 0) > 0:
        signals.append("Hidden iframe detected on page")
    return signals[:3]

@app.get("/")
def root():
    return {
        "status":      "Phishing Detector API v8",
        "redis":       "connected" if cache else "disabled",
        "vt_enabled":  bool(VT_API_KEY),
        "gsb_enabled": bool(GSB_API_KEY),
        "nlp_enabled": NLP_ENABLED,
        "trusted_domains_loaded": len(TRUSTED_DOMAINS),
        "model_version": model_registry.active_version,
        "feature_store": "redis" if cache else "disabled",
    }

@app.get("/model-info")
def model_info():
    return model_registry.metadata()

@app.get("/metrics")
def metrics_endpoint():
    return Response(metrics.render_prometheus(), media_type="text/plain")

@app.post("/check")
async def check_url(request: URLRequest, db: Session = Depends(get_db)):
    request_start = time.perf_counter()
    metrics.increment("phishing_check_requests_total")
    url = normalize_url(request.url)
    key = cache_key(url)

    try:
        cached = cache.get(key) if cache else None
        if cached:
            result = json.loads(cached)
            result["cached"] = True
            result["cache_tier"] = "exact_url"
            metrics.increment("phishing_cache_hits_total", {"tier": "exact_url"})
            metrics.increment("phishing_verdict_total", {"verdict": result.get("verdict", "UNKNOWN")})
            metrics.observe("phishing_check_latency", time.perf_counter() - request_start)
            return result
    except Exception as e:
        print(f"Cache read error: {e}")

    neg_key = negative_cache_key(url)
    try:
        neg_cached = cache.get(neg_key) if cache else None
        if neg_cached:
            result = json.loads(neg_cached)
            result["cached"] = True
            result["cache_tier"] = "negative"
            metrics.increment("phishing_cache_hits_total", {"tier": "negative"})
            metrics.increment("phishing_verdict_total", {"verdict": result.get("verdict", "UNKNOWN")})
            metrics.observe("phishing_check_latency", time.perf_counter() - request_start)
            return result
    except Exception as e:
        print(f"Negative cache read error: {e}")

    hostname          = hostname_from_url(url)
    registered_domain = registered_domain_from_host(hostname)
    is_cloud_subdomain = is_cloud_hostname(hostname)

    dom_key = domain_cache_key(registered_domain)
    try:
        domain_cached = cache.get(dom_key) if cache else None
        if domain_cached:
            domain_result = json.loads(domain_cached)
            if domain_result.get("verdict") == "BLOCK":
                result = dict(domain_result)
                result["url"] = url
                result["cached"] = True
                result["cache_tier"] = "domain_level"
                metrics.increment("phishing_cache_hits_total", {"tier": "domain_level"})
                metrics.increment("phishing_verdict_total", {"verdict": result.get("verdict", "UNKNOWN")})
                metrics.observe("phishing_check_latency", time.perf_counter() - request_start)
                return result
    except Exception as e:
        print(f"Domain cache read error: {e}")

    features = extract_features(url)

    domain_for_runtime = registered_domain
    runtime_feats = await feature_store.get_or_compute(domain_for_runtime, get_runtime_domain_features)
    features["time_domain_activation"] = runtime_feats["time_domain_activation"]
    features["time_domain_expiration"] = runtime_feats["time_domain_expiration"]
    features["ttl_hostname"]           = runtime_feats["ttl_hostname"]
    features["time_response"]          = runtime_feats["time_response"]

    feature_values = [[features.get(col, -1) for col in FEATURE_COLS]]
    rf_prob        = float(rf.predict_proba(feature_values)[0][1])
    xgb_prob       = float(xgb.predict_proba(feature_values)[0][1])
    ensemble_prob  = (rf_prob + xgb_prob) / 2

    stop_event = asyncio.Event()

    vt, page_text, gsb = await asyncio.gather(
        check_virustotal(url, stop_event),
        fetch_page_text(url),
        check_google_safe_browsing(url)
    )

    if stop_event.is_set():
        phash_result = {"is_clone": False, "brand": None, "distance": None}
        image_result = {}
        dom_result = {}
    else:
        phash_result, image_result, dom_result = await asyncio.gather(
            check_phash(url),
            run_image_scan(url, stop_event),
            check_dom_signals(url)
        )

    fast_result = {"early_exit": False, "partial_score": 0, "signals": []}

    nlp_prob = nlp_score(page_text)
    typo     = check_typosquatting(url)
    adv      = extract_advanced_features(url)
    domain_similarity = domain_similarity_check(url)
    feature_diagnostics = diagnose_lexical_feature_risk(url, features, adv)
    attack_patterns = classify_attack_pattern(
        url, features, adv, typo, domain_similarity, dom_result, phash_result
    )

    ml_score    = ensemble_prob * 100
    vt_boost    = 0.0
    nlp_boost   = 0.0
    phash_boost = 0.0
    gsb_boost   = 0.0
    typo_boost  = 0.0
    similarity_boost = 0.0
    attack_boost = 0.0
    adv_boost   = 0.0

    if vt["vt_checked"] and vt["vt_total"] > 0:
        vt_boost = (vt["vt_malicious"] / vt["vt_total"]) * 30

    if nlp_prob > 0.7:
        nlp_boost = (nlp_prob - 0.7) * 20

    if phash_result.get("is_clone") and phash_result.get("brand"):
        phash_boost = 40.0

    image_boost = 0.0
    if image_result.get("qr_url_flagged"):
        image_boost += 25.0
    if image_result.get("ocr_suspicious"):
        image_boost += 20.0
    if image_result.get("steganography_detected"):
        image_boost += 15.0
    image_boost = min(image_boost, 40.0)

    dom_boost = 0.0
    if dom_result.get("has_login_form") and dom_result.get("form_action_mismatch"):
        dom_boost += 40.0
    # Hidden iframes alone are very common on legitimate sites (ads, tracking,
    # payment widgets) — only treat as suspicious when there are MANY of them
    # (a pattern more consistent with malicious injection) or combined with
    # a login-form mismatch already flagged above
    if dom_result.get("hidden_iframe_count", 0) >= 3:
        dom_boost += 15.0
    dom_boost = min(dom_boost, 50.0)

    if gsb.get("gsb_match"):
        gsb_boost = 40.0

    if typo.get("is_typosquat"):
        typo_boost = 25.0

    if domain_similarity.get("suspicious"):
        similarity_boost = domain_similarity.get("boost", 25.0)

    attack_boost = attack_patterns.get("score", 0.0)

    if adv.get("has_homoglyph"):
        adv_boost += 30.0
    if adv.get("is_cloud_hosted") and adv.get("cloud_suspicious"):
        adv_boost += 30.0
    if adv.get("is_high_entropy") or adv.get("is_low_vowel"):
        adv_boost += 15.0
    if adv.get("has_ip_in_domain"):
        adv_boost += 35.0
    adv_boost = min(adv_boost, 50.0)

    positive_rule_score_raw = (
        vt_boost + nlp_boost + phash_boost + gsb_boost +
        typo_boost + similarity_boost + attack_boost +
        adv_boost + image_boost + dom_boost
    )
    positive_rule_score = bound_positive_rule_score(positive_rule_score_raw)
    has_positive_rules = positive_rule_score > 0
    calibrated_ml_score = calibrate_ml_score(ml_score, has_positive_rules)
    trust_conflict = has_trust_conflict(
        vt, gsb, typo, adv, phash_result, dom_result, image_result,
        domain_similarity, attack_patterns
    )
    trusted_candidate = trust_match_for_hostname(hostname)
    tls_validation = (
        await validate_tls_certificate(hostname)
        if trusted_candidate and urlparse(url).scheme == "https"
        else {"checked": False, "valid": False, "issuer": None, "error": None}
    )
    trust_delta, trusted_match = trusted_domain_delta(
        hostname,
        trust_conflict or is_cloud_subdomain,
        tls_validation,
        urlparse(url).scheme,
    )

    score = arbitrate_score(calibrated_ml_score, positive_rule_score, trust_delta)
    signals = get_signals(
        url, score, vt, nlp_prob, phash_result, gsb, typo, adv, fast_result,
        image_result, dom_result, domain_similarity, attack_patterns
    )

    verdict, ttl = verdict_for_score(score)

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
            "rf_score":            round(rf_prob * 100, 1),
            "xgb_score":           round(xgb_prob * 100, 1),
            "ml_score_raw":         round(ensemble_prob * 100, 1),
            "ml_score_calibrated":  round(calibrated_ml_score, 1),
            "positive_rule_score_raw": round(positive_rule_score_raw, 1),
            "positive_rule_score":  round(positive_rule_score, 1),
            "trusted_domain_match": trusted_match,
            "trust_delta":          round(trust_delta, 1),
            "trust_conflict":       bool(trust_conflict),
            "tls_checked":          bool(tls_validation.get("checked")),
            "tls_valid":            bool(tls_validation.get("valid")),
            "tls_issuer":           tls_validation.get("issuer"),
            "vt_malicious":        vt["vt_malicious"],
            "vt_total":            vt["vt_total"],
            "vt_boost":            round(vt_boost, 1),
            "nlp_score":           round(nlp_prob * 100, 1),
            "nlp_boost":           round(nlp_boost, 1),
            "phash_clone":         bool(phash_result.get("is_clone", False)),
            "phash_brand":         phash_result.get("brand"),
            "phash_boost":         phash_boost,
            "gsb_match":           gsb.get("gsb_match", False),
            "gsb_threat":          gsb.get("threat_type"),
            "gsb_boost":           gsb_boost,
            "typosquat":           typo.get("is_typosquat", False),
            "typo_brand":          typo.get("closest_brand"),
            "typo_boost":          typo_boost,
            "domain_similarity":   domain_similarity,
            "similarity_boost":    round(similarity_boost, 1),
            "attack_patterns":     attack_patterns.get("patterns", []),
            "attack_classifier":   attack_patterns.get("classifier"),
            "attack_boost":        round(attack_boost, 1),
            "lexical_diagnostics": feature_diagnostics,
            "homoglyph":           bool(adv.get("has_homoglyph", False)),
            "unicode_spoof":       bool(adv.get("has_unicode", False)),
            "cloud_hosted":        bool(adv.get("is_cloud_hosted", False)),
            "high_entropy":        bool(adv.get("is_high_entropy", False)),
            "has_ip_in_domain":    bool(adv.get("has_ip_in_domain", False)),
            "adv_boost":           adv_boost,
            "fast_check_used":     False,
            "fast_boost":          0.0,
            "early_exit_triggered": stop_event.is_set(),
            "domain_age_days":     features["time_domain_activation"],
            "age_source":          runtime_feats.get("age_source"),
            "feature_store_hit":    bool(runtime_feats.get("feature_store_hit", False)),
            "model_version":        model_registry.active_version,
            "qr_flagged":          bool(image_result.get("qr_url_flagged", False)),
            "ocr_suspicious":      bool(image_result.get("ocr_suspicious", False)),
            "steganography":       bool(image_result.get("steganography_detected", False)),
            "image_boost":         image_boost,
            "has_login_form":      bool(dom_result.get("has_login_form", False)),
            "form_action_mismatch": bool(dom_result.get("form_action_mismatch", False)),
            "form_action_domain":  dom_result.get("form_action_domain"),
            "hidden_iframe_count": dom_result.get("hidden_iframe_count", 0),
            "dom_boost":           dom_boost
        }
    }

    try:
        if cache: cache.set(key, json.dumps(result), ex=ttl)
        if cache and verdict == "BLOCK":
            cache.set(dom_key, json.dumps(result), ex=ttl)
    except:
        pass

    metrics.increment("phishing_verdict_total", {"verdict": verdict})
    metrics.observe("phishing_check_latency", time.perf_counter() - request_start)
    print(json.dumps({
        "event": "phishing_check",
        "registered_domain": registered_domain,
        "score": score,
        "verdict": verdict,
        "model_version": model_registry.active_version,
        "positive_rule_score": round(positive_rule_score, 1),
        "trust_delta": round(trust_delta, 1),
        "attack_patterns": attack_patterns.get("patterns", []),
        "feature_store_hit": bool(runtime_feats.get("feature_store_hit", False)),
    }))

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

@app.get("/feedback-logs")
def get_feedback_logs(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(FeedbackLog).order_by(FeedbackLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id":        l.id,
            "url":       l.url,
            "feedback":  l.feedback,
            "timestamp": str(l.timestamp)
        }
        for l in logs
    ]

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
