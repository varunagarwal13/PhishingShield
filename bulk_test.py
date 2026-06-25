"""
bulk_test.py — Bulk URL tester for Phishing Detector API
"""

import asyncio
import aiohttp
import pandas as pd
import argparse
import json
import time
import sys
from tqdm.asyncio import tqdm as atqdm
from datetime import datetime

DEFAULT_API     = "http://localhost:8000"
DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 15
DEFAULT_OUTPUT  = "results.csv"

async def check_url(session, api, url, timeout):
    try:
        async with session.post(
            f"{api}/check",
            json={"url": url},
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {
                    "url":          url,
                    "score":        data.get("score", -1),
                    "verdict":      data.get("verdict", "ERROR"),
                    "signals":      "; ".join(data.get("signals", [])),
                    "rf_score":     data.get("details", {}).get("rf_score", -1),
                    "xgb_score":    data.get("details", {}).get("xgb_score", -1),
                    "nlp_score":    data.get("details", {}).get("nlp_score", -1),
                    "vt_malicious": data.get("details", {}).get("vt_malicious", 0),
                    "vt_total":     data.get("details", {}).get("vt_total", 0),
                    "cached":       data.get("cached", False),
                    "error":        None
                }
            else:
                return _error_row(url, f"HTTP {resp.status}")
    except asyncio.TimeoutError:
        return _error_row(url, "Timeout")
    except Exception as e:
        return _error_row(url, str(e))

def _error_row(url, error):
    return {
        "url": url, "score": -1, "verdict": "ERROR",
        "signals": "", "rf_score": -1, "xgb_score": -1,
        "nlp_score": -1, "vt_malicious": 0, "vt_total": 0,
        "cached": False, "error": error
    }

async def run_all(urls, api, workers, timeout):
    semaphore = asyncio.Semaphore(workers)
    results = []

    async def bounded(url):
        async with semaphore:
            return await check_url(session, api, url, timeout)

    connector = aiohttp.TCPConnector(limit=workers + 10)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [bounded(u) for u in urls]
        for coro in atqdm.as_completed(tasks, total=len(tasks), desc="Testing URLs"):
            results.append(await coro)

    return results

def compute_metrics(df):
    if "label" not in df.columns:
        return
    labeled = df[df["verdict"] != "ERROR"].copy()
    if labeled.empty:
        print("\n[!] No valid results to benchmark.")
        return
    labeled["predicted"] = labeled["verdict"].apply(lambda v: 1 if v in ("BLOCK", "WARN") else 0)
    labeled["label"] = labeled["label"].astype(int)
    tp = ((labeled["predicted"] == 1) & (labeled["label"] == 1)).sum()
    tn = ((labeled["predicted"] == 0) & (labeled["label"] == 0)).sum()
    fp = ((labeled["predicted"] == 1) & (labeled["label"] == 0)).sum()
    fn = ((labeled["predicted"] == 0) & (labeled["label"] == 1)).sum()
    total     = len(labeled)
    accuracy  = (tp + tn) / total * 100 if total else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) else 0
    recall    = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0
    fpr       = fp / (fp + tn) * 100 if (fp + tn) else 0
    print("\n" + "=" * 45)
    print("  ACCURACY BENCHMARK")
    print("=" * 45)
    print(f"  Total evaluated : {total:,}")
    print(f"  True Positives  : {tp:,}")
    print(f"  True Negatives  : {tn:,}")
    print(f"  False Positives : {fp:,}")
    print(f"  False Negatives : {fn:,}")
    print("-" * 45)
    print(f"  Accuracy        : {accuracy:.2f}%")
    print(f"  Precision       : {precision:.2f}%")
    print(f"  Recall          : {recall:.2f}%")
    print(f"  F1 Score        : {f1:.2f}%")
    print(f"  False Pos Rate  : {fpr:.2f}%")
    print("=" * 45)

def print_summary(df, elapsed):
    total  = len(df)
    errors = (df["verdict"] == "ERROR").sum()
    valid  = total - errors
    blocks = (df["verdict"] == "BLOCK").sum()
    warns  = (df["verdict"] == "WARN").sum()
    allows = (df["verdict"] == "ALLOW").sum()
    print("\n" + "=" * 45)
    print("  TEST SUMMARY")
    print("=" * 45)
    print(f"  Total URLs      : {total:,}")
    print(f"  Successful      : {valid:,}")
    print(f"  Errors/Timeouts : {errors:,}")
    print("-" * 45)
    print(f"  BLOCK           : {blocks:,}  ({blocks/valid*100:.1f}%)" if valid else "  BLOCK : 0")
    print(f"  WARN            : {warns:,}  ({warns/valid*100:.1f}%)"  if valid else "  WARN  : 0")
    print(f"  ALLOW           : {allows:,}  ({allows/valid*100:.1f}%)" if valid else "  ALLOW : 0")
    print("-" * 45)
    print(f"  Avg Score       : {df[df['score'] >= 0]['score'].mean():.1f} / 100")
    print(f"  Time Elapsed    : {elapsed:.1f}s")
    print(f"  Throughput      : {valid/elapsed:.1f} URLs/sec" if elapsed > 0 else "")
    print("=" * 45)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",   required=True)
    parser.add_argument("--output",  default=DEFAULT_OUTPUT)
    parser.add_argument("--api",     default=DEFAULT_API)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    print(f"\nLoading: {args.input}")
    try:
        df_in = pd.read_csv(args.input)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.input}")
        sys.exit(1)

    if "url" not in df_in.columns:
        print("[ERROR] Input CSV must have a 'url' column.")
        sys.exit(1)

    urls = df_in["url"].dropna().astype(str).tolist()
    has_labels = "label" in df_in.columns
    labels_map = dict(zip(df_in["url"].astype(str), df_in.get("label", pd.Series()))) if has_labels else {}

    print(f"Loaded {len(urls):,} URLs  |  Labels: {'yes' if has_labels else 'no'}")
    print(f"API: {args.api}  |  Workers: {args.workers}  |  Timeout: {args.timeout}s\n")

    start = time.time()
    results = asyncio.run(run_all(urls, args.api, args.workers, args.timeout))
    elapsed = time.time() - start

    df_out = pd.DataFrame(results)
    if has_labels:
        df_out["label"] = df_out["url"].map(labels_map)

    df_out.to_csv(args.output, index=False)
    print(f"\nResults saved to {args.output}")

    print_summary(df_out, elapsed)
    compute_metrics(df_out)

if __name__ == "__main__":
    main()
