"""URL feature extraction service."""

from __future__ import annotations

from typing import Callable


class FeatureService:
    """Adapter around the legacy feature extractor."""

    def __init__(self, extractor: Callable[[str, list[str]], dict] | None = None) -> None:
        self.extractor = extractor

    def extract(self, url: str, feature_columns: list[str] | None = None) -> dict:
        if self.extractor:
            return self.extractor(url, feature_columns or [])
        return {"length_url": len(url), "url_shortened": 0}

