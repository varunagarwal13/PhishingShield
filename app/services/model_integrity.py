"""Model artifact integrity checks."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


class ModelIntegrityError(RuntimeError):
    """Raised when a model artifact does not match its manifest."""


class ModelIntegrityVerifier:
    """Verify hashes and metadata before model loading."""

    def __init__(self, manifest: dict[str, Any], base_path: Path | str = ".") -> None:
        self.manifest = manifest
        self.base_path = Path(base_path)

    def verify(self) -> None:
        active_version = self.manifest.get("active_version")
        model_config = self.manifest.get("models", {}).get(active_version, {})
        expected_version = model_config.get("model_version", active_version)
        if expected_version and expected_version != active_version:
            raise ModelIntegrityError("Model version does not match active manifest version.")
        for name, artifact in model_config.items():
            if not isinstance(artifact, str) or not artifact.endswith(".pkl"):
                continue
            expected_hash = model_config.get(f"{name}_sha256")
            if not expected_hash:
                continue
            path = self.base_path / artifact
            if not path.exists():
                raise ModelIntegrityError(f"Missing model artifact: {artifact}")
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise ModelIntegrityError(f"SHA256 mismatch for {artifact}")

