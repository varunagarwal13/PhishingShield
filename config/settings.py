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


class Settings(BaseSettings):
    """Runtime configuration for development, testing, and production."""

    environment: Literal["development", "testing", "production"] = "development"
    api_key: str = ""
    vt_api_key: str = ""
    google_safe_browsing_key: str = ""
    redis_url: str = "redis://127.0.0.1:6379"
    database_url: str = "sqlite:///./threat_log.db"
    trusted_domains_path: Path = Path("config/trusted_domains.json")
    alexa_top10k_path: Path = Path("config/allowlist/alexa_top10k.txt")
    cache_ttl_seconds: int = 3600
    trusted_cache_ttl_seconds: int = 21600
    http_timeout_seconds: float = 5.0
    verify_ssl: bool = True
    allow_insecure_ssl: bool = False

    # Default weights configuration for the scoring engine
    weights: dict[str, float] = {
        "virustotal_per_flag": 10.0,
        "virustotal_max": 50.0,
        "gsb_hit": 40.0,
        "phishtank_hit": 35.0,
        "visual_clone": 40.0,
        "domain_age_7days": 30.0,
        "cert_age_24h": 20.0,
        "nlp_urgency": 20.0,
        "url_model_scale": 30.0,
        "password_field_unknown": 10.0,
        "form_action_mismatch": 10.0,
        "iframe_abuse": 15.0,
    }

    if isinstance(SettingsConfigDict, type(dict)):
        model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    """Return cached settings for dependency injection."""
    return Settings()
