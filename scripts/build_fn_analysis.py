"""Generate false negatives analysis dynamically by auditing model misses."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import urlparse
import numpy as np
import joblib
import tldextract

from training.feature_engineering.features import extract_url_features

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fn_analysis")

extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def run_fn_analysis():
    logger.info("Initializing false negative clustering audit...")
    
    model_path = Path("training/export/structured_model.pkl")
    meta_path = Path("training/export/model_metadata.json")
    test_path = Path("training/validation/test_split.json")
    urls_txt_path = Path("C:/Users/varun/OneDrive/Desktop/urls.txt")
    
    model = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    schema = meta.get("feature_schema", [])
    threshold = meta.get("optimal_threshold", 0.50)
    
    # Collect all phishing URLs
    phishing_items = []
    with open(test_path, "r", encoding="utf-8") as f:
        test_data = json.load(f)
    for item in test_data:
        if int(item["label"]) == 1:
            phishing_items.append(item["url"])
            
    if urls_txt_path.exists():
        with open(urls_txt_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    phishing_items.append(line)
                    
    # Cap evaluated set to 4000
    import random
    random.seed(42)
    phishing_items = random.sample(phishing_items, min(len(phishing_items), 4000))
    
    missed_urls = []
    
    logger.info(f"Auditing {len(phishing_items)} phishing URLs for false negatives...")
    for idx, url in enumerate(phishing_items):
        try:
            feat = extract_url_features(url)
            vector = [feat[col] for col in schema]
            prob = float(production_prob(model, vector))
            
            if prob < threshold:
                missed_urls.append((url, prob, feat))
        except Exception as e:
            logger.error(f"Error checking {url}: {e}")
            
    logger.info(f"Identified {len(missed_urls)} false negatives.")
    
    # Cluster missed URLs
    clusters = {
        "short domains": [],
        "numeric domains": [],
        "parked domains": [],
        "no brand words": [],
        "low entropy": [],
        "URL shorteners": [],
        "IP hosts": [],
        "uncommon TLDs": [],
        "redirectors": []
    }
    
    for url, prob, feat in missed_urls:
        has_ip = feat.get("has_ip", 0.0) == 1.0
        entropy = feat.get("entropy", 0.0)
        
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        
        ext = extract_domain(hostname)
        domain = ext.domain.lower() if ext.domain else ""
        tld = ext.suffix.lower() if ext.suffix else ""
        
        # Determine main cluster membership
        if has_ip:
            clusters["IP hosts"].append(url)
        elif any(s in hostname for s in ["bit.ly", "t.co", "tinyurl", "shorturl", "goo.gl"]):
            clusters["URL shorteners"].append(url)
        elif sum(c.isdigit() for c in domain) / len(domain) > 0.4 if len(domain) > 0 else False:
            clusters["numeric domains"].append(url)
        elif len(domain) <= 6:
            clusters["short domains"].append(url)
        elif tld in ["tk", "cf", "gq", "ga", "ml", "xyz", "top", "cc", "fit"]:
            clusters["uncommon TLDs"].append(url)
        elif "redirect" in url.lower() or "url=" in url.lower() or "next=" in url.lower():
            clusters["redirectors"].append(url)
        elif entropy < 2.5:
            clusters["low entropy"].append(url)
        elif not any(b in url.lower() for b in ["paypal", "google", "amazon", "chase"]):
            clusters["no brand words"].append(url)
        else:
            clusters["parked domains"].append(url)
            
    # Generate false_negative_analysis.md
    report_path = Path("false_negative_analysis.md")
    logger.info(f"Writing false negative report to {report_path}...")
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# PhishingShield Production False Negative Analysis\n\n")
        f.write("This document profiles model misses, clustering them by features to analyze structural bypass vectors.\n\n")
        
        f.write("## 1. Misses Clustering Overview\n\n")
        f.write("| Failure Cluster Group | Sample Misses Count | Primary Cause | Proposed Feature Solution |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        
        m_causes = {
            "short domains": "Domain string contains too few characters to capture similarity patterns.",
            "numeric domains": "DGA or IP domain strings lack standard lexical word tokens.",
            "parked domains": "Heuristics resemble clean default parked names page formats.",
            "no brand words": "Obfuscated target links do not contain brand spoof keywords.",
            "low entropy": "Subdomains resemble flat simple dictionary names.",
            "URL shorteners": "Redirect link services obscure true final destination paths.",
            "IP hosts": "Bypasses standard TLD validation heuristics.",
            "uncommon TLDs": "Rare registry domains that have low frequency distributions.",
            "redirectors": "Heuristics hide phishing path within valid redirect structures."
        }
        
        m_solutions = {
            "short domains": "Incorporate subdomain depth checks.",
            "numeric domains": "Utilize character transitions matrices.",
            "parked domains": "Incorporate browser behavior and redirects depth.",
            "no brand words": "Leverage content analysis NLP classifiers.",
            "low entropy": "Apply Jaro-Winkler homoglyph cleaning checks.",
            "URL shorteners": "Resolve destination URL before feature extraction.",
            "IP hosts": "Trigger threat intelligence lookups on raw IP blocks.",
            "uncommon TLDs": "Incorporate TLD rarity score mapping.",
            "redirectors": "Extract features from path segments and query keys."
        }
        
        for cluster_name, urls in clusters.items():
            cause = m_causes.get(cluster_name, "Lexical features overlap with clean domains.")
            sol = m_solutions.get(cluster_name, "Incorporate deep NLP classifiers.")
            f.write(f"| **{cluster_name}** | {len(urls)} | {cause} | {sol} |\n")
            
        f.write("\n## 2. Sample Failure Signatures List\n\n")
        for cluster_name, urls in clusters.items():
            f.write(f"### {cluster_name} Sample Targets\n")
            if urls:
                for u in urls[:3]:
                    f.write(f"- `{u}`\n")
            else:
                f.write("- *Zero misses recorded in this cluster group*\n")
            f.write("\n")
            
    logger.info("✓ False negative analysis report compiled.")


def production_prob(model, vector) -> float:
    X = np.array([vector], dtype=np.float32)
    return float(model.predict_proba(X)[0][1])


if __name__ == "__main__":
    run_fn_analysis()
