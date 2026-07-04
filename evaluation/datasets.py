"""Dataset loader and format auto-detector for external model evaluation."""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("evaluation_datasets")


def load_dataset(file_path: Path | str) -> tuple[list[str], list[int] | None, dict]:
    """Auto-detect format (JSON, CSV, TSV, URL list), parse URLs & labels, and count anomalies."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    raw_urls: list[str] = []
    labels: list[int] | None = []
    has_labels = False

    # Inspect suffix
    suffix = path.suffix.lower()

    try:
        if suffix == ".json":
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        url = item.get("url", "").strip()
                        label = item.get("label", None)
                        if url:
                            raw_urls.append(url)
                            if label is not None:
                                labels.append(int(label))
                                has_labels = True
        elif suffix in (".csv", ".tsv"):
            delimiter = "\t" if suffix == ".tsv" else ","
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                # Read sample to detect headers
                sample = f.read(2048)
                f.seek(0)
                has_header = csv.has_header(sample) if sample else False
                
                reader = csv.reader(f, delimiter=delimiter)
                headers = []
                if has_header:
                    headers = [h.strip().lower() for h in next(reader)]
                
                url_col_idx = 0
                label_col_idx = -1
                
                if has_header:
                    # Detect URL column index
                    for col in ("url", "link", "address", "domain"):
                        if col in headers:
                            url_col_idx = headers.index(col)
                            break
                    # Detect label column index
                    for col in ("label", "class", "phishing", "target"):
                        if col in headers:
                            label_col_idx = headers.index(col)
                            has_labels = True
                            break

                for row in reader:
                    if not row:
                        continue
                    if len(row) > url_col_idx:
                        url = row[url_col_idx].strip()
                        if url:
                            raw_urls.append(url)
                            if has_labels and label_col_idx != -1 and len(row) > label_col_idx:
                                val = row[label_col_idx].strip()
                                labels.append(int(val) if val.isdigit() else 0)
        else:
            # Fallback to plain URL list (one URL per line)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Check if line contains space-separated URL + label
                        parts = line.split()
                        if len(parts) >= 2 and parts[-1].isdigit() and parts[0].startswith(("http", "www")):
                            raw_urls.append(parts[0])
                            labels.append(int(parts[-1]))
                            has_labels = True
                        elif len(parts) >= 2 and parts[0].isdigit() and parts[1].startswith(("http", "www")):
                            raw_urls.append(parts[1])
                            labels.append(int(parts[0]))
                            has_labels = True
                        else:
                            raw_urls.append(line)

    except Exception as e:
        logger.error(f"Failed to read dataset file: {e}")
        raise

    # Deduplicate and validate URLs
    unique_urls = []
    unique_labels = [] if has_labels else None
    
    seen = set()
    malformed_count = 0
    duplicate_count = 0

    for idx, url in enumerate(raw_urls):
        # Validate URL structure
        try:
            parsed = urlparse(url)
            # Accept schemeless/standard strings, flag as malformed if empty host and path
            if not parsed.netloc and not parsed.path:
                malformed_count += 1
                continue
        except Exception:
            malformed_count += 1
            continue

        if url in seen:
            duplicate_count += 1
            continue
            
        seen.add(url)
        unique_urls.append(url)
        if has_labels and idx < len(labels):
            unique_labels.append(labels[idx])

    stats = {
        "format": suffix[1:] if suffix else "txt (plain list)",
        "total_lines_read": len(raw_urls),
        "total_urls": len(unique_urls),
        "duplicates": duplicate_count,
        "malformed": malformed_count,
        "labels_present": has_labels
    }

    return unique_urls, unique_labels, stats
