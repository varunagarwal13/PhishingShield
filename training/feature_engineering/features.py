"""Feature engineering: Extract 110 advanced lexical, structural, and brand features from URLs."""

from __future__ import annotations

import math
import re
from urllib.parse import urlparse
import tldextract

from config.constants import RISKY_TLDS

# Compile regexes for performance
IP_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
SPECIAL_CHARS_RE = re.compile(r"[-_.\?=%&@!]")
HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")

BRAND_KEYWORDS = [
    "paypal", "google", "amazon", "facebook", "netflix",
    "apple", "microsoft", "instagram", "twitter", "linkedin",
    "chase", "wellsfargo", "bankofamerica", "coinbase", "metamask",
    "yahoo", "github", "steam", "adobe", "dropbox"
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "wallet", "billing", "invoice", "support",
    "reconnect", "authentication", "verification", "portal", "account",
    "signin", "payment", "banking"
]

QWERTY_COORDS = {
    'q': (0,0), 'w': (0,1), 'e': (0,2), 'r': (0,3), 't': (0,4), 'y': (0,5), 'u': (0,6), 'i': (0,7), 'o': (0,8), 'p': (0,9),
    'a': (1,0), 's': (1,1), 'd': (1,2), 'f': (1,3), 'g': (1,4), 'h': (1,5), 'j': (1,6), 'k': (1,7), 'l': (1,8),
    'z': (2,0), 'x': (2,1), 'c': (2,2), 'v': (2,3), 'b': (2,4), 'n': (2,5), 'm': (2,6)
}

HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x", "\u0456": "i"
}

extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v / total) * math.log2(v / total) for v in freq.values())


def transition_entropy(s: str) -> float:
    if len(s) < 2:
        return 0.0
    transitions = {}
    for i in range(len(s) - 1):
        pair = s[i:i+2]
        transitions[pair] = transitions.get(pair, 0) + 1
    total = len(s) - 1
    return -sum((v / total) * math.log2(v / total) for v in transitions.values())


def ngram_entropy(s: str, n: int) -> float:
    if len(s) < n:
        return 0.0
    ngrams = {}
    for i in range(len(s) - n + 1):
        gram = s[i:i+n]
        ngrams[gram] = ngrams.get(gram, 0) + 1
    total = len(s) - n + 1
    return -sum((v / total) * math.log2(v / total) for v in ngrams.values())


def max_consecutive_consonants(s: str) -> int:
    consonants = set("bcdfghjklmnpqrstvwxyz")
    max_count = 0
    current = 0
    for c in s.lower():
        if c in consonants:
            current += 1
            max_count = max(max_count, current)
        else:
            current = 0
    return max_count


def max_consecutive_digits(s: str) -> int:
    max_count = 0
    current = 0
    for c in s:
        if c.isdigit():
            current += 1
            max_count = max(max_count, current)
        else:
            current = 0
    return max_count


def clean_homoglyphs(s: str) -> str:
    return "".join(HOMOGLYPH_MAP.get(c, c) for c in s)


def levenshtein_similarity(s1: str, s2: str) -> float:
    if not s1 or not s2:
        return 0.0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return 0.0
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for idx, c2 in enumerate(s2):
            insertations = prev[idx + 1] + 1
            deletions = curr[-1] + 1
            substitutions = prev[idx] + (c1 != c2)
            curr.append(min(insertations, deletions, substitutions))
        prev = curr
    dist = prev[-1]
    max_len = max(len(s1), len(s2))
    return 1.0 - (dist / max_len) if max_len > 0 else 0.0


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    if not s1 or not s2:
        return 0.0
    if s1 == s2:
        return 1.0
        
    len1, len2 = len(s1), len(s2)
    max_dist = (max(len1, len2) // 2) - 1
    if max_dist < 0:
        max_dist = 0
        
    match1 = [False] * len1
    match2 = [False] * len2
    
    matches = 0
    for i in range(len1):
        start = max(0, i - max_dist)
        end = min(len2, i + max_dist + 1)
        for j in range(start, end):
            if not match2[j] and s1[i] == s2[j]:
                match1[i] = True
                match2[j] = True
                matches += 1
                break
                
    if matches == 0:
        return 0.0
        
    t = 0
    k = 0
    for i in range(len1):
        if match1[i]:
            while not match2[k]:
                k += 1
            if s1[i] != s2[k]:
                t += 1
            k += 1
    t //= 2
    
    jaro = (matches / len1 + matches / len2 + (matches - t) / matches) / 3.0
    prefix = 0
    for i in range(min(4, min(len1, len2))):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
            
    return jaro + prefix * 0.1 * (1.0 - jaro)


def keyboard_distance_similarity(s1: str, s2: str) -> float:
    if not s1 or not s2:
        return 0.0
    dist = 0.0
    min_len = min(len(s1), len(s2))
    for i in range(min_len):
        c1, c2 = s1[i].lower(), s2[i].lower()
        if c1 != c2:
            if c1 in QWERTY_COORDS and c2 in QWERTY_COORDS:
                p1, p2 = QWERTY_COORDS[c1], QWERTY_COORDS[c2]
                dist += math.sqrt((p1[0]-p2[0])**2 + (p1[1]-p2[1])**2)
            else:
                dist += 2.0
    dist += abs(len(s1) - len(s2)) * 2.0
    max_possible = max(len(s1), len(s2)) * 2.0
    return 1.0 - (dist / max_possible) if max_possible > 0 else 0.0


def extract_url_features(url: str) -> dict[str, float]:
    features = {}

    try:
        parsed = urlparse(url)
    except Exception:
        return {col: 0.0 for col in FEATURE_COLUMNS}

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    ext = extract_domain(hostname)
    domain = ext.domain.lower() if ext.domain else ""
    tld = "." + ext.suffix.lower() if ext.suffix else ""

    # Group 1: Domain structural features
    features["url_len"] = float(len(url))
    features["host_len"] = float(len(hostname))
    features["path_len"] = float(len(path))
    features["query_len"] = float(len(query))
    features["fragment_len"] = float(len(fragment))
    features["tld_len"] = float(len(tld))
    features["registered_domain_len"] = float(len(domain))
    features["subdomain_depth"] = float(hostname.count("."))

    # Numeric & character ratio flags
    features["has_ip"] = 1.0 if IP_RE.match(hostname) else 0.0
    digits = sum(c.isdigit() for c in hostname)
    features["numeric_hostname_ratio"] = float(digits / len(hostname) if len(hostname) > 0 else 0)
    
    consonants_ratio = max_consecutive_consonants(hostname) / len(hostname) if len(hostname) > 0 else 0.0
    features["consecutive_consonant_ratio"] = float(consonants_ratio)

    digits_ratio = max_consecutive_digits(hostname) / len(hostname) if len(hostname) > 0 else 0.0
    features["consecutive_digit_ratio"] = float(digits_ratio)

    # Entropies
    features["entropy"] = float(shannon_entropy(domain))
    features["char_transition_entropy"] = float(transition_entropy(hostname))
    features["bigram_entropy"] = float(ngram_entropy(hostname, 2))
    features["trigram_entropy"] = float(ngram_entropy(hostname, 3))

    # TLD rarity check
    features["tld_rarity_score"] = float(5.0 if tld in RISKY_TLDS else 1.0)

    # Group 2: URL structure complexity
    features["path_complexity"] = float(len(path) / len(url) if len(url) > 0 else 0)
    features["query_complexity"] = float(len(query) / len(url) if len(url) > 0 else 0)
    features["fragment_complexity"] = float(len(fragment) / len(url) if len(url) > 0 else 0)
    features["param_count"] = float(query.count("=") if query else 0)

    # Suspicious query parameters or redirects
    redir_hits = sum(1 for w in ["redirect", "redir", "url", "link", "to", "next"] if w in query.lower() or w in path.lower())
    features["redirect_keyword_count"] = float(redir_hits)

    susp_params = sum(1 for w in ["login", "secure", "user", "email"] if w in query.lower())
    features["suspicious_parameter_names"] = float(susp_params)

    # Group 3: Keywords checks
    phish_hits = sum(1 for w in PHISHING_KEYWORDS if w in url.lower())
    features["phishing_keyword_count"] = float(phish_hits)

    # Group 4: Brand Impersonation similarity Matrix
    clean_domain = clean_homoglyphs(domain)
    
    for brand in BRAND_KEYWORDS:
        features[f"sim_levenshtein_{brand}"] = float(levenshtein_similarity(clean_domain, brand))
        features[f"sim_jarowinkler_{brand}"] = float(jaro_winkler_similarity(clean_domain, brand))
        features[f"sim_keyboard_{brand}"] = float(keyboard_distance_similarity(clean_domain, brand))
        features[f"sim_homoglyph_{brand}"] = float(levenshtein_similarity(clean_domain, brand))

    return features


# List of columns
BASE_COLUMNS = [
    "url_len", "host_len", "path_len", "query_len", "fragment_len", "tld_len",
    "registered_domain_len", "subdomain_depth", "has_ip", "numeric_hostname_ratio",
    "consecutive_consonant_ratio", "consecutive_digit_ratio", "entropy",
    "char_transition_entropy", "bigram_entropy", "trigram_entropy", "tld_rarity_score",
    "path_complexity", "query_complexity", "fragment_complexity", "param_count",
    "redirect_keyword_count", "suspicious_parameter_names", "phishing_keyword_count"
]

BRAND_MATRIX_COLUMNS = []
for b in BRAND_KEYWORDS:
    BRAND_MATRIX_COLUMNS.extend([
        f"sim_levenshtein_{b}", f"sim_jarowinkler_{b}",
        f"sim_keyboard_{b}", f"sim_homoglyph_{b}"
    ])

FEATURE_COLUMNS = BASE_COLUMNS + BRAND_MATRIX_COLUMNS
