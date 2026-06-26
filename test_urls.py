import asyncio, aiohttp, csv, argparse, time, os, signal, sys
from datetime import datetime

API_URL = "http://localhost:8000/check"
API_KEY = ""
HEADERS = {"Content-Type": "application/json"}
if API_KEY:
    HEADERS["X-API-Key"] = API_KEY

stop_flag = False

def handle_sigint(sig, frame):
    global stop_flag
    print("\n\n  Stopping gracefully... saving progress.")
    stop_flag = True

signal.signal(signal.SIGINT, handle_sigint)

async def check_url(session, url, semaphore):
    async with semaphore:
        try:
            async with session.post(API_URL, json={"url": url}, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {"url": url, "score": data.get("score",""), "verdict": data.get("verdict",""), "signals": " | ".join(data.get("signals",[])), "rf_score": data.get("details",{}).get("rf_score",""), "xgb_score": data.get("details",{}).get("xgb_score",""), "vt_malicious": data.get("details",{}).get("vt_malicious",""), "nlp_score": data.get("details",{}).get("nlp_score",""), "cached": data.get("cached",False), "error": ""}
                elif resp.status == 400:
                    body = await resp.json()
                    return {"url": url, "score": "", "verdict": "INVALID", "signals": "", "rf_score": "", "xgb_score": "", "vt_malicious": "", "nlp_score": "", "cached": "", "error": body.get("detail","Bad request")}
                else:
                    return {"url": url, "score": "", "verdict": "ERROR", "signals": "", "rf_score": "", "xgb_score": "", "vt_malicious": "", "nlp_score": "", "cached": "", "error": f"HTTP {resp.status}"}
        except asyncio.TimeoutError:
            return {"url": url, "score": "", "verdict": "TIMEOUT", "signals": "", "rf_score": "", "xgb_score": "", "vt_malicious": "", "nlp_score": "", "cached": "", "error": "Timed out"}
        except Exception as e:
            return {"url": url, "score": "", "verdict": "ERROR", "signals": "", "rf_score": "", "xgb_score": "", "vt_malicious": "", "nlp_score": "", "cached": "", "error": str(e)}

async def run(urls, concurrency, output_file):
    global stop_flag
    fieldnames = ["url","score","verdict","signals","rf_score","xgb_score","vt_malicious","nlp_score","cached","error"]

    # load already done URLs to support resume
    done_urls = set()
    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                done_urls.add(row["url"])
        print(f"  Resuming — {len(done_urls)} already done, skipping them.")

    remaining = [u for u in urls if u not in done_urls]
    total = len(urls)
    already_done = len(done_urls)

    # open CSV in append mode
    write_header = not os.path.exists(output_file)
    csvfile = open(output_file, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    if write_header:
        writer.writeheader()

    results = []
    start = time.time()
    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_url(session, url, semaphore) for url in remaining]
        for coro in asyncio.as_completed(tasks):
            if stop_flag:
                break
            result = await coro
            results.append(result)
            writer.writerow(result)
            csvfile.flush()

            done = already_done + len(results)
            elapsed = time.time() - start
            rate = len(results) / elapsed if elapsed > 0 else 0
            eta = int((total - done) / rate) if rate > 0 else 0
            verdicts = {}
            for r in results:
                verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
            summary = "  ".join(f"{k}:{v}" for k, v in sorted(verdicts.items()))
            blocks = int((done / total) * 30)
            bar = "█" * blocks + "░" * (30 - blocks)
            print(f"\r[{bar}] {done}/{total} ({rate:.1f}/s ETA {eta}s)  {summary}", end="", flush=True)

    csvfile.close()
    print()

    elapsed = time.time() - start
    verdicts = {}
    for r in results:
        verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
    print(f"\n{'─'*50}")
    print(f"  Tested : {len(results)} URLs in {elapsed:.1f}s ({len(results)/elapsed:.1f}/s)")
    print(f"  Output : {output_file}")
    print(f"{'─'*50}")
    for verdict, count in sorted(verdicts.items()):
        pct = count / len(results) * 100 if results else 0
        print(f"  {verdict:<10} {count:>5}  ({pct:5.1f}%)")
    print(f"{'─'*50}")
    top = sorted([r for r in results if r["score"] != ""], key=lambda x: float(x["score"]), reverse=True)[:10]
    if top:
        print(f"\n  Top {len(top)} highest risk URLs:")
        for r in top:
            print(f"  [{r['verdict']:<5}] {r['score']:>5}  {r['url'][:80]}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--input", type=str, default="urls.txt")
    parser.add_argument("--output", type=str, default="results_all.csv")
    args = parser.parse_args()
    with open(args.input, "r", encoding="utf-8") as f:
        all_urls = [line.strip() for line in f if line.strip()]
    urls = all_urls if args.all else all_urls[:args.limit]
    print(f"\n  Phishing Classifier — Batch Tester")
    print(f"  URLs to test : {len(urls)}")
    print(f"  Concurrency  : {args.concurrency}")
    print(f"  Output       : {args.output}")
    print(f"  API          : {API_URL}\n")
    asyncio.run(run(urls, args.concurrency, args.output))

if __name__ == "__main__":
    main()
