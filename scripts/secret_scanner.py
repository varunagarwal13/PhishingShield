"""Secret scanner utility using standard ASCII output."""

from __future__ import annotations

import os
import re

SECRETS_PATTERN = re.compile(r'(?i)(api_key|secret|token|password)\s*=\s*[\'\"]([a-zA-Z0-9_-]{12,})[\'\"]')


def scan_for_secrets() -> None:
    found = 0
    for root, _, files in os.walk('.'):
        for f in files:
            path = os.path.join(root, f)
            if '__pycache__' in path or '.git' in path or 'node_modules' in path:
                continue
            if not (f.endswith('.py') or f.endswith('.json') or f.endswith('.js')):
                continue
            try:
                with open(path, 'r', encoding='utf-8') as handle:
                    for line_num, line in enumerate(handle, 1):
                        match = SECRETS_PATTERN.search(line)
                        if match:
                            val = match.group(2)
                            if "your_" in val or "placeholder" in val:
                                continue
                            print(f"[!] Target Secret Match in {path} at line {line_num}")
                            found += 1
            except Exception:
                pass

    if found == 0:
        print("[OK] Secret scan completed. No hardcoded secrets found in codebase!")
    else:
        print(f"[WARN] Secret scan completed. Found {found} match(es)!")


if __name__ == "__main__":
    scan_for_secrets()
