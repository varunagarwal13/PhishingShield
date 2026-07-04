"""Utility script to verify local environment dependencies."""

from __future__ import annotations

import logging
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("env_check")

REQUIRED_PACKAGES = [
    "fastapi", "uvicorn", "redis", "aiohttp",
    "joblib", "sklearn", "xgboost", "tldextract",
    "sqlalchemy", "whois", "PIL"
]


def check_dependencies() -> None:
    logger.info(f"Checking Python Environment (v{sys.version.split()[0]})...")
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            if pkg == "sklearn":
                import sklearn
            elif pkg == "PIL":
                import PIL
            else:
                __import__(pkg)
            logger.info(f"  ✓ {pkg} is installed")
        except ImportError:
            missing.append(pkg)
            logger.warning(f"  ✗ {pkg} is MISSING")

    if missing:
        logger.error(f"Missing packages: {', '.join(missing)}")
        sys.exit(1)
    else:
        logger.info("✓ All standard dependencies verified successfully!")


if __name__ == "__main__":
    check_dependencies()
