"""Application settings loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ModuleNotFoundError:
    from pydantic import BaseModel as BaseSettings

    SettingsConfigDict = dict


class DetectorWeights(BaseSettings):
    """Configurable detector contribution weights."""

    ml: float = 0.40
    reputation: float = 0.25
    html: float = 0.15
    ocr: float = 0.10
    heuristic: float = 0.10
    dns: float = 0.05
    ssl: float = 0.05
    whois: float = 0.05
    favicon: float = 0.05


class Settings(BaseSettings):
    """Runtime configuration for development, testing, and production."""

    environment: Literal["development", "testing", "production"] = "development"
    api_key: str = ""
    vt_api_key: str = ""
    redis_url: str = "redis://127.0.0.1:6379"
    database_url: str = "sqlite:///./threat_log.db"
    trusted_domains_path: Path = Path("trusted_domains.json")
    detector_weights: DetectorWeights = DetectorWeights()
    enabled_detectors: tuple[str, ...] = (
        "ml",
        "heuristic",
        "reputation",
        "html",
        "dns",
        "ssl",
        "whois",
        "favicon",
        "ocr",
    )
    cache_ttl_seconds: int = 3600
    trusted_cache_ttl_seconds: int = 21600
    http_timeout_seconds: float = 5.0
    verify_ssl: bool = True
    allow_insecure_ssl: bool = False
    model_manifest_path: Path = Path("model_manifest.json")

    if isinstance(SettingsConfigDict, type(dict)):
        model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    """Return cached settings for dependency injection."""
    return Settings()

