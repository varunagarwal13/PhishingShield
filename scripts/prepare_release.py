"""Prepare the repository for an open-source GitHub release by cleaning temporary folders and writing templates."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil

# Files cleanup list
TEMP_PATTERNS = [
    r"\.pytest_cache",
    r"\.mypy_cache",
    r"\.ruff_cache",
    r"__pycache__",
    r"\.coverage",
    r"threat_log\.db-journal",
    r"\.log$"
]


def clean_temp_files():
    print("Starting repository cleanup...")
    root = Path(".")
    
    # Remove pycache and caches
    for item in root.glob("**/*"):
        if item.is_dir() and item.name in [".pytest_cache", ".mypy_cache", ".ruff_cache", "__pycache__"]:
            print(f"Removing cache directory: {item}")
            shutil.rmtree(item, ignore_errors=True)
            
    # Remove files matching temp patterns
    for item in root.glob("**/*"):
        if item.is_file():
            if item.suffix in [".log", ".bak"] or item.name == ".coverage":
                print(f"Removing temp file: {item}")
                item.unlink(missing_ok=True)


def write_gitignore():
    print("Writing updated .gitignore...")
    content = """# PhishingShield Release GitIgnore
__pycache__/
*.pyc
*.pyo
.pytest_cache/
.mypy_cache/
.ruff_cache/

.env
.env.*

venv/
.venv/

*.db
*.sqlite
*.sqlite3

logs/
cache/

training/cache/
training/tmp/

*.log
*.csv.tmp
*.png.tmp
*.pdf.tmp
*.bak
"""
    with open(".gitignore", "w", encoding="utf-8") as f:
        f.write(content)


def write_github_templates():
    print("Writing GitHub templates...")
    github_dir = Path(".github")
    issues_dir = github_dir / "ISSUE_TEMPLATE"
    issues_dir.mkdir(parents=True, exist_ok=True)
    
    # Bug Report Template
    bug_content = """---
name: Bug report
about: Create a report to help us improve PhishingShield
title: '[BUG] '
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior.

**Expected behavior**
A clear and concise description of what you expected to happen.
"""
    with open(issues_dir / "bug_report.md", "w", encoding="utf-8") as f:
        f.write(bug_content)
        
    # Feature Request Template
    feat_content = """---
name: Feature request
about: Suggest an idea for PhishingShield
title: '[FEAT] '
labels: enhancement
assignees: ''
---

**Is your feature request related to a problem? Please describe.**
A clear and concise description of what the problem is.

**Describe the solution you'd like**
A clear and concise description of what you want to happen.
"""
    with open(issues_dir / "feature_request.md", "w", encoding="utf-8") as f:
        f.write(feat_content)
        
    # PR Template
    pr_content = """## Description
Provide a summary of the changes introduced by this Pull Request.

## Types of changes
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
"""
    with open(github_dir / "PULL_REQUEST_TEMPLATE.md", "w", encoding="utf-8") as f:
        f.write(pr_content)


def scan_for_secrets() -> bool:
    print("Scanning codebase for secrets...")
    root = Path(".")
    # Scan for common patterns (AWS keys, OpenAI keys, VT keys, long hex/alphanumeric keys)
    secret_pattern = re.compile(r"(api[-_]?key|vt[-_]?key|openai[-_]?key|aws[-_]?access|password|token)\s*=\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", re.IGNORECASE)
    
    clean = True
    for item in root.glob("**/*.py"):
        if "prepare_release.py" in item.name:
            continue
        try:
            with open(item, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                matches = secret_pattern.findall(content)
                if matches:
                    print(f"⚠️ POTENTIAL SECRET FOUND in {item}: {matches}")
                    clean = False
        except Exception:
            pass
            
    return clean


def main():
    clean_temp_files()
    write_gitignore()
    write_github_templates()
    
    secrets_clean = scan_for_secrets()
    if not secrets_clean:
        print("[-] Secrets found! Resolve potential API leaks before pushing.")
        sys.exit(1)
    else:
        print("OK: Secrets scan passed. No raw API keys discovered.")


if __name__ == "__main__":
    main()
