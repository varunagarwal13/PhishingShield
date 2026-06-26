"""
Accuracy tester — all URLs in urls.txt are PHISHING.
Tests first 3000 URLs and measures detection rate.

Correct   = WARN or BLOCK  (classifier caught it)
Missed    = ALLOW          (classifier missed it — false negative)

Usage:
    python test_accuracy.py
"""

import asyncio
import aiohttp
import csv
import time
import os

# --- Config ---
API_BASE   = "http://localhost:8000"
API_KEY    = os.getenv("API_KEY", "")
INPUT_FILE = "urls.txt"
OUTPUT_FILE= "test_results.csv"
LIMIT      = 3000
CONCURRENCY= 20
TIMEOUT    = 10

HEADERS = {"X-API-Key": API_KEY} if API_KEY else {}


async def check_url(session, url, semaphore):
    async with semaphore:
        try:
            async with session.post(
                f"{API_BASE}/check",
                json={"url": url},
                headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "url": url,
                        "score": data.get("score", -1),
                        "verdict": data.get("verdict", "ERROR"),
                        "signals": ", ".join(data.get("signals", [])),
                        "cached": data.get("cached", False),
                        "error": ""
                    }
                elif resp.status == 429:
                    await asyncio.sleep(2)
                    return {"url": url, "score": -1, "verdict": "RATE_LIMITED", "signals": "", "cached": False, "error": "rate limited"}
                else:
                    return {"url": url, "score": -1, "verdict": "ERROR", "signals": "", "cached": False, "error": f"HTTP {resp.status}"}
        except asyncio.TimeoutError:
            return {"url": url, "score": -1, "verdict": "ERROR", "signals": "", "cached": False, "error": "timeout"}
        except Exception as e:
            return {"url": url, "score": -1, "verdict": "ERROR", "signals": "", "cached": False, "error": str(e)}


def load_urls(filepath, limit):
    urls = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "http://" + url
            urls.append(url)
            if len(urls) >= limit:
                break
    return urls


async def run_tests(urls):
    semaphore = asyncio.Semaphore(CONCURRENCY)
    results = []
    start = time.time()

    print(f"\n{'='*55}")
    print(f"  Phishing Classifier — Detection Rate Test")
    print(f"{'='*55}")
    print(f"  URLs to test   : {len(urls)}")
    print(f"  Ground truth   : ALL PHISHING")
    print(f"  Concurrency    : {CONCURRENCY}")
    print(f"  API            : {API_BASE}")
    print(f"{'='*55}\n")

    async with aiohttp.ClientSession() as session:
        tasks = [check_url(session, url, semaphore) for url in urls]
        completed = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            completed += 1
            if completed % 200 == 0 or completed == len(urls):
                elapsed = time.time() - start
                rate = completed / elapsed
                eta = (len(urls) - completed) / rate if rate > 0 else 0
                print(f"  [{completed:>4}/{len(urls)}]  {rate:.1f} req/s  ETA: {eta:.0f}s")

    elapsed = time.time() - start
    print(f"\n  Done in {elapsed:.1f}s  ({len(results)/elapsed:.1f} req/s)\n")
    return results


def print_report(results):
    total   = len(results)
    errors  = [r for r in results if r["verdict"] in ("ERROR", "RATE_LIMITED")]
    valid   = [r for r in results if r["verdict"] not in ("ERROR", "RATE_LIMITED")]

    block   = sum(1 for r in valid if r["verdict"] == "BLOCK")
    warn    = sum(1 for r in valid if r["verdict"] == "WARN")
    allow   = sum(1 for r in valid if r["verdict"] == "ALLOW")

    detected = block + warn     # classifier flagged as suspicious
    missed   = allow            # classifier let through — false negatives
    v_total  = len(valid)

    detection_rate = detected / v_total * 100 if v_total else 0
    miss_rate      = missed   / v_total * 100 if v_total else 0
    block_rate     = block    / v_total * 100 if v_total else 0
    warn_rate      = warn     / v_total * 100 if v_total else 0

    # Score distribution
    scores = [r["score"] for r in valid if r["score"] >= 0]
    avg_score = sum(scores) / len(scores) if scores else 0
    scores_sorted = sorted(scores)
    median_score  = scores_sorted[len(scores_sorted)//2] if scores_sorted else 0

    print(f"{'='*55}")
    print(f"  DETECTION RESULTS  (all {v_total} valid URLs are phishing)")
    print(f"{'='*55}")
    print(f"  ✅ Detected (WARN+BLOCK) : {detected:>5}  ({detection_rate:.2f}%)")
    print(f"     └─ BLOCK              : {block:>5}  ({block_rate:.2f}%)")
    print(f"     └─ WARN               : {warn:>5}  ({warn_rate:.2f}%)")
    print(f"  ❌ Missed   (ALLOW)      : {missed:>5}  ({miss_rate:.2f}%)")
    print(f"  ⚠️  Errors/Timeouts       : {len(errors):>5}")
    print(f"\n  Score stats:")
    print(f"     Average score : {avg_score:.1f}")
    print(f"     Median score  : {median_score:.1f}")
    print(f"\n  Overall Detection Rate : {detection_rate:.2f}%")
    print(f"  Miss Rate (FN)         : {miss_rate:.2f}%")
    print(f"{'='*55}\n")

    # Missed URLs preview
    missed_urls = [r for r in valid if r["verdict"] == "ALLOW"]
    if missed_urls:
        print(f"  Sample of missed phishing URLs (ALLOW):")
        for r in missed_urls[:10]:
            print(f"    score={r['score']:>5.1f}  {r['url']}")
        if len(missed_urls) > 10:
            print(f"    ... and {len(missed_urls)-10} more (see test_results.csv)")
    print()


def save_csv(results):
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url","score","verdict","detected","signals","cached","error"])
        writer.writeheader()
        for r in results:
            detected = "yes" if r["verdict"] in ("BLOCK","WARN") else ("no" if r["verdict"] == "ALLOW" else "error")
            writer.writerow({
                "url":      r["url"],
                "score":    r["score"],
                "verdict":  r["verdict"],
                "detected": detected,
                "signals":  r["signals"],
                "cached":   r["cached"],
                "error":    r["error"]
            })
    print(f"  Full results saved to: {OUTPUT_FILE}\n")


async def main():
    # Health check
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_BASE}/health", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status != 200:
                    print(f"ERROR: API not healthy (status {resp.status})")
                    return
                print(f"  API is up ✅")
    except Exception as e:
        print(f"ERROR: Cannot reach API — {e}")
        print("Run this first:  uvicorn main:app --host 0.0.0.0 --port 8000")
        return

    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found.")
        return

    urls = load_urls(INPUT_FILE, LIMIT)
    print(f"  Loaded {len(urls)} URLs from {INPUT_FILE}")

    results = await run_tests(urls)
    print_report(results)
    save_csv(results)


if __name__ == "__main__":
    asyncio.run(main())
