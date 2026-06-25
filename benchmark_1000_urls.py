import asyncio
import json
import random
import string
import warnings
from collections import Counter, defaultdict
from pathlib import Path

warnings.filterwarnings("ignore")

import main
SEED = 20260625
TOTAL_URLS = 1000

ROOT = Path(__file__).resolve().parent
OUTPUTS = ROOT.parent.parent / "outputs"
OUTPUTS.mkdir(parents=True, exist_ok=True)

BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple", "facebook",
    "netflix", "sbi", "hdfc", "icici", "paytm", "instagram",
    "linkedin", "github", "coinbase", "metamask"
]
PHISHING_TLDS = ["xyz", "top", "click", "site", "online", "live", "work"]
COMMON_TLDS = ["com", "net", "org", "io", "in", "co"]
SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "confirm"]


class DummyDB:
    def add(self, _):
        pass

    def commit(self):
        pass


def load_daily_domains(limit=400):
    domains = []
    with (ROOT / "alexa_top10k.txt").open("r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain and "." in domain and domain not in domains:
                domains.append(domain)
            if len(domains) >= limit:
                break
    return domains


def rand_token(rng, min_len=5, max_len=11):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(min_len, max_len)))


def generate_phishing_urls(rng, count=300):
    urls = []
    templates = [
        "https://secure-{brand}-login-{token}.{tld}/verify",
        "http://{brand}-account-update-{token}.{tld}/signin",
        "https://login-{brand}-security.{tld}/confirm",
        "http://{brand}.{token}.cloud-login.{tld}/account",
        "https://{brand}-wallet-verify-{token}.{tld}/password/reset",
    ]
    for _ in range(count):
        brand = rng.choice(BRANDS)
        tld = rng.choice(PHISHING_TLDS)
        token = rand_token(rng)
        urls.append(rng.choice(templates).format(brand=brand, token=token, tld=tld))
    return urls


def generate_unknown_urls(rng, count=200):
    urls = []
    for _ in range(count):
        name = rand_token(rng, 7, 14)
        if rng.random() < 0.25:
            name = f"{rand_token(rng, 4, 7)}-{rand_token(rng, 4, 7)}"
        tld = rng.choice(COMMON_TLDS + ["site", "online"])
        path = rng.choice(["", "/home", "/docs", "/products", "/blog", "/contact"])
        urls.append(f"https://{name}.{tld}{path}")
    return urls


def generate_legitimate_sensitive_urls():
    base = [
        "https://accounts.google.com",
        "https://login.microsoftonline.com",
        "https://github.com/login",
        "https://www.paypal.com/signin",
        "https://onlinesbi.sbi.bank.in",
        "https://retail.sbi.bank.in",
        "https://www.hdfcbank.com",
        "https://www.icicibank.com",
        "https://paytm.com",
        "https://www.amazon.com",
        "https://appleid.apple.com",
        "https://www.linkedin.com/login",
        "https://www.instagram.com/accounts/login",
        "https://www.netflix.com/login",
        "https://account.microsoft.com",
        "https://www.chase.com",
        "https://www.bankofamerica.com",
        "https://www.cloudflare.com",
        "https://platform.openai.com",
        "https://www.office.com",
    ]
    urls = []
    paths = ["", "/login", "/account", "/signin", "/help", "/security"]
    for domain in base:
        for path in paths:
            urls.append(domain.rstrip("/") + path)
    return urls[:100]


def build_dataset():
    rng = random.Random(SEED)
    rows = []

    for domain in load_daily_domains(400):
        rows.append({
            "url": f"https://{domain}",
            "category": "daily_usage",
            "expected": "benign",
        })

    for url in generate_legitimate_sensitive_urls():
        rows.append({
            "url": url,
            "category": "legitimate_sensitive",
            "expected": "benign",
        })

    for url in generate_phishing_urls(rng, 300):
        rows.append({
            "url": url,
            "category": "synthetic_phishing",
            "expected": "phishing",
        })

    for url in generate_unknown_urls(rng, 200):
        rows.append({
            "url": url,
            "category": "unknown_random",
            "expected": "unknown",
        })

    rng.shuffle(rows)
    return rows[:TOTAL_URLS]


async def fake_runtime_features(domain):
    suspicious_tld = domain.rsplit(".", 1)[-1] in PHISHING_TLDS
    suspicious_brand = any(brand in domain for brand in BRANDS)
    return {
        "time_domain_activation": 3 if suspicious_tld or suspicious_brand else 3650,
        "time_domain_expiration": 300,
        "ttl_hostname": 300,
        "asn_ip": -1,
        "time_response": 120,
        "age_source": "benchmark_stub",
        "feature_store_hit": False,
    }


async def fake_virustotal(url, stop_event=None):
    lowered = url.lower()
    malicious = 8 if any(tld in lowered for tld in [".xyz", ".top", ".click"]) else 0
    if malicious >= 5 and stop_event is not None:
        stop_event.set()
    return {"vt_malicious": malicious, "vt_total": 70 if malicious else 0, "vt_checked": bool(malicious)}


async def fake_gsb(url):
    lowered = url.lower()
    hit = any(word in lowered for word in ["password/reset", "account-update", "wallet-verify"])
    return {"gsb_match": hit, "threat_type": "SOCIAL_ENGINEERING" if hit else None}


async def fake_page_text(url):
    lowered = url.lower()
    if any(word in lowered for word in SUSPICIOUS_WORDS):
        return "urgent verify your account password immediately secure login confirmation"
    return "welcome home products documentation support trusted information"


async def fake_phash(_url):
    return {"is_clone": False, "brand": None, "distance": None}


async def fake_image_scan(_url, _stop_event):
    return {
        "qr_urls": [],
        "qr_url_flagged": False,
        "ocr_text": "",
        "ocr_suspicious": False,
        "steganography_detected": False,
    }


async def fake_dom_signals(url):
    lowered = url.lower()
    mismatch = any(word in lowered for word in ["password/reset", "account-update"])
    return {
        "has_login_form": mismatch,
        "form_action_mismatch": mismatch,
        "form_action_domain": "collector.example" if mismatch else None,
        "hidden_iframe_count": 0,
        "checked": True,
    }


async def fake_tls(hostname):
    return {"checked": True, "valid": True, "issuer": "Benchmark CA", "error": None}


def patch_external_dependencies():
    main.print = lambda *args, **kwargs: None
    main.cache = None
    main.feature_store.cache = None
    main.get_runtime_domain_features = fake_runtime_features
    main.check_virustotal = fake_virustotal
    main.check_google_safe_browsing = fake_gsb
    main.fetch_page_text = fake_page_text
    main.check_phash = fake_phash
    main.run_image_scan = fake_image_scan
    main.check_dom_signals = fake_dom_signals
    main.validate_tls_certificate = fake_tls


async def run_benchmark():
    patch_external_dependencies()
    dataset = build_dataset()
    db = DummyDB()
    results = []

    for index, row in enumerate(dataset, start=1):
        response = await main.check_url(main.URLRequest(url=row["url"]), db=db)
        details = response.get("details", {})
        results.append({
            **row,
            "normalized_url": response["url"],
            "score": response["score"],
            "verdict": response["verdict"],
            "signals": response.get("signals", []),
            "ml_score_raw": details.get("ml_score_raw"),
            "ml_score_calibrated": details.get("ml_score_calibrated"),
            "positive_rule_score": details.get("positive_rule_score"),
            "trust_delta": details.get("trust_delta"),
            "trusted_domain_match": details.get("trusted_domain_match"),
            "attack_patterns": details.get("attack_patterns", []),
            "domain_similarity": details.get("domain_similarity", {}),
            "lexical_diagnostics": details.get("lexical_diagnostics", {}),
        })
        if index % 100 == 0:
            print(f"Processed {index}/{len(dataset)}")

    return results


def summarize(results):
    verdict_counts = Counter(row["verdict"] for row in results)
    category_counts = Counter(row["category"] for row in results)
    by_category = defaultdict(Counter)
    for row in results:
        by_category[row["category"]][row["verdict"]] += 1

    expected_benign = [r for r in results if r["expected"] == "benign"]
    expected_phishing = [r for r in results if r["expected"] == "phishing"]
    benign_bad = [r for r in expected_benign if r["verdict"] in {"WARN", "BLOCK"}]
    phishing_caught = [r for r in expected_phishing if r["verdict"] in {"WARN", "BLOCK"}]

    top_signals = Counter()
    top_patterns = Counter()
    for row in results:
        top_signals.update(row["signals"])
        top_patterns.update(row["attack_patterns"])

    return {
        "total": len(results),
        "seed": SEED,
        "verdict_counts": dict(verdict_counts),
        "category_counts": dict(category_counts),
        "by_category": {k: dict(v) for k, v in by_category.items()},
        "benign_warn_or_block_count": len(benign_bad),
        "benign_warn_or_block_rate": round(len(benign_bad) / max(len(expected_benign), 1), 4),
        "synthetic_phishing_warn_or_block_count": len(phishing_caught),
        "synthetic_phishing_warn_or_block_rate": round(len(phishing_caught) / max(len(expected_phishing), 1), 4),
        "top_signals": top_signals.most_common(12),
        "top_attack_patterns": top_patterns.most_common(12),
        "highest_risk": sorted(results, key=lambda r: r["score"], reverse=True)[:15],
        "benign_warn_or_block_examples": benign_bad[:15],
        "unknown_block_examples": [r for r in results if r["category"] == "unknown_random" and r["verdict"] == "BLOCK"][:15],
    }


def write_outputs(results, summary):
    json_path = OUTPUTS / "url_benchmark_1000_results.json"
    md_path = OUTPUTS / "url_benchmark_1000_report.md"
    json_path.write_text(json.dumps({"summary": summary, "results": results}, indent=2), encoding="utf-8")

    lines = [
        "# 1,000 URL Benchmark Report",
        "",
        f"Seed: `{summary['seed']}`",
        f"Total URLs: `{summary['total']}`",
        "",
        "## Verdict Distribution",
        "",
    ]
    for verdict, count in sorted(summary["verdict_counts"].items()):
        lines.append(f"- `{verdict}`: {count}")

    lines.extend(["", "## Category Breakdown", ""])
    for category, counts in sorted(summary["by_category"].items()):
        line = ", ".join(f"{verdict}: {count}" for verdict, count in sorted(counts.items()))
        lines.append(f"- `{category}`: {line}")

    lines.extend([
        "",
        "## Quality Checks",
        "",
        f"- Benign URLs warned/blocked: `{summary['benign_warn_or_block_count']}` "
        f"({summary['benign_warn_or_block_rate'] * 100:.2f}%)",
        f"- Synthetic phishing URLs warned/blocked: `{summary['synthetic_phishing_warn_or_block_count']}` "
        f"({summary['synthetic_phishing_warn_or_block_rate'] * 100:.2f}%)",
        "",
        "## Top Signals",
        "",
    ])
    for signal, count in summary["top_signals"]:
        lines.append(f"- {signal}: {count}")

    lines.extend(["", "## Top Attack Patterns", ""])
    for pattern, count in summary["top_attack_patterns"]:
        lines.append(f"- `{pattern}`: {count}")

    lines.extend(["", "## Highest-Risk Examples", ""])
    for row in summary["highest_risk"]:
        lines.append(f"- `{row['verdict']}` `{row['score']}` `{row['category']}` {row['url']}")

    lines.extend(["", "## Benign WARN/BLOCK Examples", ""])
    if summary["benign_warn_or_block_examples"]:
        for row in summary["benign_warn_or_block_examples"]:
            lines.append(f"- `{row['verdict']}` `{row['score']}` `{row['category']}` {row['url']}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Notes",
        "",
        "- External live network dependencies were stubbed for this benchmark.",
        "- Synthetic phishing URLs are generated phishing-like samples, not live phishing pages.",
        "- This test exercises the API scoring pipeline, ML inference, arbitration, trust policy, domain similarity, and attack-pattern layers.",
        "- Use the JSON file for per-URL details.",
    ])
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path


def main_entry():
    results = asyncio.run(run_benchmark())
    summary = summarize(results)
    json_path, md_path = write_outputs(results, summary)
    compact_summary = dict(summary)
    compact_summary["highest_risk"] = [
        {
            "url": row["url"],
            "category": row["category"],
            "score": row["score"],
            "verdict": row["verdict"],
            "signals": row["signals"],
        }
        for row in summary["highest_risk"][:5]
    ]
    compact_summary["benign_warn_or_block_examples"] = [
        {
            "url": row["url"],
            "category": row["category"],
            "score": row["score"],
            "verdict": row["verdict"],
            "signals": row["signals"],
        }
        for row in summary["benign_warn_or_block_examples"][:5]
    ]
    compact_summary["unknown_block_examples"] = [
        {
            "url": row["url"],
            "category": row["category"],
            "score": row["score"],
            "verdict": row["verdict"],
            "signals": row["signals"],
        }
        for row in summary["unknown_block_examples"][:5]
    ]
    print(json.dumps(compact_summary, indent=2))
    print(f"JSON_RESULTS={json_path}")
    print(f"MARKDOWN_REPORT={md_path}")


if __name__ == "__main__":
    main_entry()
