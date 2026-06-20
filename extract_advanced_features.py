import re
import math
import tldextract
from urllib.parse import urlparse

# Digit/symbol homoglyph map
HOMOGLYPH_MAP = {
    '0':'o','1':'l','3':'e','4':'a','5':'s',
    '6':'g','7':'t','8':'b','@':'a','!':'i',
}

BRANDS = ["paypal","google","amazon","facebook","netflix",
          "apple","microsoft","instagram","twitter","linkedin",
          "chase","wellsfargo","bankofamerica","hdfc","icici","sbi",
          "paytm","flipkart","irctc","steam","coinbase","metamask"]

CLOUD_PROVIDERS = [
    "sites.google.com","web.app","firebaseapp.com","pages.dev",
    "workers.dev","azurewebsites.net","github.io","netlify.app",
    "vercel.app","glitch.me","weebly.com","wixsite.com",
    "sharepoint.com","blob.core.windows.net","s3.amazonaws.com",
    "googleusercontent.com","host.secureserver.net","blogspot.com",
    "myftpupload.com"
]

RISKY_TLDS = {"tk","ml","ga","cf","gq","top","xyz","club","online",
              "site","work","party","live","click","link","win","loan"}


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v/len(s))*math.log2(v/len(s)) for v in freq.values())


def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2)+1))
    for c1 in s1:
        curr = [prev[0]+1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1 != c2)))
        prev = curr
    return prev[-1]


def extract_advanced_features(url):
    try:
        parsed      = urlparse(url)
        ext         = tldextract.extract(url)
        domain      = ext.domain.lower()
        suffix      = ext.suffix.lower()
        subdomain   = ext.subdomain.lower()
        full_domain = f"{domain}.{suffix}"
        url_lower   = url.lower()

        # 1. Homoglyph normalization (digit/symbol substitution)
        normalized = domain
        for fake, real in HOMOGLYPH_MAP.items():
            normalized = normalized.replace(fake, real)
        has_digit_homoglyph = normalized != domain

        # 1b. Unicode homoglyph detection (Cyrillic/Greek lookalikes)
        has_unicode = any(ord(c) > 127 for c in domain)

        has_homoglyph = has_digit_homoglyph or has_unicode

        # 2. Min Levenshtein distance to brands (normalized + original)
        min_brand_dist          = min(levenshtein(normalized, b) for b in BRANDS)
        min_brand_dist_original = min(levenshtein(domain, b) for b in BRANDS)

        # 3. Cloud hosting with suspicious content
        is_cloud = any(
            full_domain.endswith(p) or f"{subdomain}.{full_domain}".endswith(p)
            for p in CLOUD_PROVIDERS
        )
        cloud_suspicious = is_cloud and any(w in url_lower for w in [
            "login","verify","secure","account","banking","password",
            "signup","activate","update","confirm"
        ])

        # 4. Domain entropy
        entropy = shannon_entropy(domain)

        # 5. Vowel ratio (random domains have few vowels)
        vowels      = sum(1 for c in domain if c in 'aeiou')
        vowel_ratio = vowels / max(len(domain), 1)

        # 6. Consecutive consonants (random pattern)
        max_consonant_run = 0
        current_run = 0
        for c in domain:
            if c.isalpha() and c not in 'aeiou':
                current_run += 1
                max_consonant_run = max(max_consonant_run, current_run)
            else:
                current_run = 0

        # 7. Digit count in domain
        digit_count = sum(1 for c in domain if c.isdigit())

        # 8. Subdomain depth
        subdomain_depth = len(subdomain.split('.')) if subdomain else 0

        # 9. Hex encoding in URL
        has_hex = bool(re.search(r'%[0-9a-fA-F]{2}', url))

        # 10. Double extension pattern
        double_ext = domain.count('.') > 0

        # 11. IP address as domain OR embedded as subdomain
        # (e.g. 151.248.71.198.host.secureserver.net is a common phishing
        # pattern that hides a raw IP inside a legitimate-looking subdomain)
        has_ip_domain    = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', ext.domain))
        has_ip_subdomain = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', subdomain))
        has_ip = has_ip_domain or has_ip_subdomain

        # 12. Suspicious keyword density
        suspicious_words = ["login","verify","secure","account","update",
                          "confirm","banking","password","credential",
                          "suspended","unlock","reactivate","billing",
                          "paypal","apple","microsoft","amazon","google",
                          "facebook","netflix","instagram","signup","activate"]
        keyword_count = sum(1 for w in suspicious_words if w in url_lower)

        return {
            "has_homoglyph":         int(has_homoglyph),
            "has_unicode":           int(has_unicode),
            "has_digit_homoglyph":   int(has_digit_homoglyph),
            "min_brand_dist":        min_brand_dist,
            "min_brand_dist_orig":   min_brand_dist_original,

            "is_cloud_hosted":       int(is_cloud),
            "cloud_suspicious":      int(cloud_suspicious),

            "domain_entropy":        round(entropy, 4),
            "vowel_ratio":           round(vowel_ratio, 4),
            "max_consonant_run":     max_consonant_run,
            "is_high_entropy":       int(entropy > 3.5),
            "is_low_vowel":          int(vowel_ratio < 0.2 and len(domain) > 5),

            "digit_count_domain":    digit_count,
            "subdomain_depth":       subdomain_depth,
            "has_hex_encoding":      int(has_hex),
            "has_double_extension":  int(double_ext),
            "has_ip_in_domain":      int(has_ip),
            "keyword_count":         keyword_count,
            "tld_risky":             int(suffix.split('.')[-1] in RISKY_TLDS),
            "url_length":            len(url),
            "has_https":             int(url.startswith("https")),
        }
    except Exception as e:
        print(f"Error: {e}")
        return {}


if __name__ == "__main__":
    test_urls = [
        "http://paypa1-secure.com/login/verify",
        "http://xqorvb.top/malware",
        "https://sites.google.com/view/paypal-login/home",
        "https://www.google.com",
        "http://secure-hdfc-bank-login.xyz/verify",
        "http://аpple.com/login",
        "http://gооgle.com/login",
        "http://151.248.71.198.host.secureserver.net/signups/activate/x",
    ]

    for url in test_urls:
        f = extract_advanced_features(url)
        print(f"\n{url[:70]}")
        print(f"  homoglyph={f.get('has_homoglyph')} unicode={f.get('has_unicode')} "
              f"brand_dist={f.get('min_brand_dist')} entropy={f.get('domain_entropy')} "
              f"cloud={f.get('is_cloud_hosted')} cloud_susp={f.get('cloud_suspicious')} "
              f"has_ip={f.get('has_ip_in_domain')} keywords={f.get('keyword_count')}")