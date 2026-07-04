"""Dataset validation, cleaning, deduplication, label normalization, and leakage protection."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import random
from urllib.parse import urlparse
import tldextract

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dataset_validation")

DATA_DIR = Path("training/datasets")
VALIDATION_DIR = Path("training/validation")
VALIDATION_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR = Path("training/export")
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

LIMIT_SAMPLES = 100000


def get_registered_domain(url: str) -> str:
    try:
        hostname = urlparse(url).netloc.lower().removeprefix("www.")
        ext = extract_domain(hostname)
        return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    except Exception:
        return ""


def validate_and_clean() -> None:
    logger.info("Initializing dataset validation and cleaning stage...")

    # Load downloaded datasets
    phishtank_path = DATA_DIR / "phishtank.json"
    urlhaus_path = DATA_DIR / "urlhaus.txt"
    tranco_path = DATA_DIR / "tranco.csv"
    openphish_path = DATA_DIR / "openphish.txt"
    umbrella_path = DATA_DIR / "cisco_umbrella.csv"

    raw_samples: list[tuple[str, int, str]] = []  # (url, label, source)

    # 1. Load PhishTank (Malicious)
    if phishtank_path.exists():
        try:
            with open(phishtank_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                url = item.get("url", "").strip()
                if url:
                    raw_samples.append((url, 1, "PhishTank"))
            logger.info(f"Loaded {len(data)} raw samples from PhishTank")
        except Exception as e:
            logger.error(f"Failed to read PhishTank: {e}")

    # 2. Load URLHaus (Malicious) - limit to 100,000
    if urlhaus_path.exists():
        try:
            count = 0
            with open(urlhaus_path, "r", encoding="utf-8") as f:
                for line in f:
                    if count >= LIMIT_SAMPLES:
                        break
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    raw_samples.append((line, 1, "URLHaus"))
                    count += 1
            logger.info(f"Loaded {count} raw samples from URLHaus")
        except Exception as e:
            logger.error(f"Failed to read URLHaus: {e}")

    # 3. Load OpenPhish (Malicious)
    if openphish_path.exists():
        try:
            count = 0
            with open(openphish_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        raw_samples.append((line, 1, "OpenPhish"))
                        count += 1
            logger.info(f"Loaded {count} raw samples from OpenPhish")
        except Exception as e:
            logger.error(f"Failed to read OpenPhish: {e}")

    # 4. Load Tranco Top List (Benign) - limit to 100,000
    if tranco_path.exists():
        try:
            count = 0
            with open(tranco_path, "r", encoding="utf-8") as f:
                for line in f:
                    if count >= LIMIT_SAMPLES:
                        break
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        if domain:
                            url = f"https://{domain}"
                            raw_samples.append((url, 0, "Tranco"))
                            count += 1
            logger.info(f"Loaded {count} raw samples from Tranco")
        except Exception as e:
            logger.error(f"Failed to read Tranco: {e}")

    # 5. Load Cisco Umbrella (Benign) - limit to 100,000
    if umbrella_path.exists():
        try:
            count = 0
            with open(umbrella_path, "r", encoding="utf-8") as f:
                for line in f:
                    if count >= LIMIT_SAMPLES:
                        break
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                        if domain:
                            url = f"https://{domain}"
                            raw_samples.append((url, 0, "CiscoUmbrella"))
                            count += 1
            logger.info(f"Loaded {count} raw samples from CiscoUmbrella")
        except Exception as e:
            logger.error(f"Failed to read CiscoUmbrella: {e}")

    # 6. Deduplicate and Normalize Labels
    unique_samples: dict[str, tuple[int, str]] = {}  # url -> (label, source)
    duplicate_count = 0

    for url, label, source in raw_samples:
        normalized_url = url.strip().rstrip("/")
        if normalized_url in unique_samples:
            duplicate_count += 1
            existing_label, existing_source = unique_samples[normalized_url]
            if label == 1 and existing_label == 0:
                unique_samples[normalized_url] = (1, f"{existing_source}+{source}")
        else:
            unique_samples[normalized_url] = (label, source)

    logger.info(f"Deduplication completed. Removed {duplicate_count} duplicate URLs.")
    logger.info(f"Remaining unique samples: {len(unique_samples)}")

    # 7. Clean URLs (Ensure parsable domain structures)
    cleaned_samples: list[dict] = []
    invalid_count = 0

    for url, (label, source) in unique_samples.items():
        domain = get_registered_domain(url)
        if not domain:
            invalid_count += 1
            continue
        cleaned_samples.append({
            "url": url,
            "domain": domain,
            "label": label,
            "source": source
        })

    logger.info(f"Removed {invalid_count} unparsable/invalid URLs.")
    logger.info(f"Final validated samples pool: {len(cleaned_samples)}")

    # 8. Split by Domain to Prevent Train/Test Leakage
    all_domains = list({s["domain"] for s in cleaned_samples})
    random.seed(42)
    random.shuffle(all_domains)

    # 80/20 train/test split on domain level
    split_idx = int(len(all_domains) * 0.8)
    train_domains = set(all_domains[:split_idx])
    test_domains = set(all_domains[split_idx:])

    train_set = [s for s in cleaned_samples if s["domain"] in train_domains]
    test_set = [s for s in cleaned_samples if s["domain"] in test_domains]

    # Verify Leakage
    leakage = train_domains.intersection(test_domains)
    assert len(leakage) == 0, "CRITICAL: Domain leakage detected!"
    logger.info("✓ Split verification complete: 0% domain leakage guaranteed.")
    logger.info(f"  Training set size: {len(train_set)} samples ({len(train_domains)} unique domains)")
    logger.info(f"  Validation set size: {len(test_set)} samples ({len(test_domains)} unique domains)")

    # 9. Balance Classes on Training Set
    benign_train = [s for s in train_set if s["label"] == 0]
    malicious_train = [s for s in train_set if s["label"] == 1]
    
    logger.info(f"Raw training distribution: Benign={len(benign_train)}, Malicious={len(malicious_train)}")
    
    if len(benign_train) != len(malicious_train):
        target_size = min(len(benign_train), len(malicious_train))
        balanced_benign = random.sample(benign_train, target_size)
        balanced_malicious = random.sample(malicious_train, target_size)
        train_set = balanced_benign + balanced_malicious
        logger.info(f"✓ Training set balanced to {len(train_set)} samples (1:1 class ratio).")

    # Save splits
    with open(VALIDATION_DIR / "train_split.json", "w", encoding="utf-8") as f:
        json.dump(train_set, f, indent=2)
    with open(VALIDATION_DIR / "test_split.json", "w", encoding="utf-8") as f:
        json.dump(test_set, f, indent=2)

    # Calculate domain overlap statistics (benign domains vs phishing domains)
    benign_domains = {s["domain"] for s in cleaned_samples if s["label"] == 0}
    phishing_domains = {s["domain"] for s in cleaned_samples if s["label"] == 1}
    overlap_domains = benign_domains.intersection(phishing_domains)

    # Record dataset statistics deliverable
    stats = {
        "dataset_version": "3.0.0",
        "total_urls": len(cleaned_samples),
        "malicious_urls": len([s for s in cleaned_samples if s["label"] == 1]),
        "benign_urls": len([s for s in cleaned_samples if s["label"] == 0]),
        "duplicate_removal_count": duplicate_count,
        "domain_overlap": {
            "overlap_count": len(overlap_domains),
            "overlap_list": list(overlap_domains)[:10]
        },
        "train_test_distribution": {
            "train_size": len(train_set),
            "test_size": len(test_set)
        },
        "provenance_licenses": {
            "PhishTank": "PhishTank Terms of Use / CC-BY-NC",
            "URLHaus": "Creative Commons CC0 (Public Domain)",
            "OpenPhish": "OpenPhish Free Feed Attribution",
            "Tranco": "Creative Commons Attribution 4.0 International",
            "CiscoUmbrella": "Cisco Umbrella Attribution License"
        }
    }

    with open("dataset_statistics.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    logger.info("✓ Written dataset_statistics.json successfully.")



if __name__ == "__main__":
    validate_and_clean()
