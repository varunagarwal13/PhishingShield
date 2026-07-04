"""Model registry and schema validation version checks."""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("model_registry")

METADATA_PATH = Path("training/export/model_metadata.json")


class ModelRegistry:
    """Verifies exported model versions, features schema compatibility, and training metrics."""

    @classmethod
    def get_metadata(cls) -> dict:
        if not METADATA_PATH.exists():
            logger.warning("No model metadata found. Model running in unverified/stub mode.")
            return {}
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read model metadata: {e}")
            return {}

    @classmethod
    def verify_version(cls, target_version: str = "2.0.0") -> bool:
        meta = cls.get_metadata()
        if not meta:
            return False
        version = meta.get("model_version", "0.0.0")
        if version != target_version:
            logger.warning(f"Version mismatch! Code expects {target_version}, got {version}.")
            return False
        logger.info(f"✓ Model version {version} verified. Training date: {meta.get('training_timestamp')}")
        return True

    @classmethod
    def get_feature_schema(cls) -> list[str]:
        meta = cls.get_metadata()
        return meta.get("feature_schema", [])
