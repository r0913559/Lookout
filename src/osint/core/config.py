"""Configuration management using Pydantic Settings."""

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from osint.core.constants import DEFAULT_RATE_LIMITS, DEFAULT_CACHE_TTL_HOURS


def find_project_root() -> Path:
    """Find the project root directory."""
    current = Path.cwd()

    # Look for pyproject.toml or config directory
    for parent in [current] + list(current.parents):
        if (parent / "pyproject.toml").exists() or (parent / "config").exists():
            return parent

    return current


def load_yaml_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    """Load configuration from YAML file."""
    if config_path is None:
        project_root = find_project_root()
        config_path = project_root / "config" / "config.yaml"

    if not config_path.exists():
        return {}

    with open(config_path, "r") as f:
        return yaml.safe_load(f) or {}


class CacheSettings(BaseSettings):
    """Cache configuration."""

    enabled: bool = True
    database_path: str = "data/cache.db"
    default_ttl_hours: int = DEFAULT_CACHE_TTL_HOURS


class ReportSettings(BaseSettings):
    """Report generation configuration."""

    default_format: str = "markdown"
    include_raw_data: bool = False
    output_directory: str = "reports"


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # API Keys
    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    urlscan_api_key: Optional[str] = Field(default=None, alias="URLSCAN_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, alias="ABUSEIPDB_API_KEY")
    shodan_api_key: Optional[str] = Field(default=None, alias="SHODAN_API_KEY")
    whoisxml_api_key: Optional[str] = Field(default=None, alias="WHOISXML_API_KEY")
    triage_api_key: Optional[str] = Field(default=None, alias="TRIAGE_API_KEY")
    alienvault_api_key: Optional[str] = Field(default=None, alias="ALIENVAULT_API_KEY")

    # Rate limits (loaded from YAML)
    rate_limits: dict[str, int] = Field(default_factory=lambda: DEFAULT_RATE_LIMITS.copy())

    # TTL overrides
    ttl_overrides: dict[str, int] = Field(default_factory=dict)

    # Cache settings
    cache: CacheSettings = Field(default_factory=CacheSettings)

    # Report settings
    reports: ReportSettings = Field(default_factory=ReportSettings)

    # API tiers (free or premium)
    api_tiers: dict[str, str] = Field(
        default_factory=lambda: {
            "virustotal": "free",
            "urlscan": "free",
            "abuseipdb": "free",
            "shodan": "free",
            "alienvault": "free",
        }
    )

    # Daily quotas (0 = unlimited)
    daily_quotas: dict[str, int] = Field(
        default_factory=lambda: {
            "virustotal": 500,
            "urlscan": 100,
            "abuseipdb": 1000,
            "shodan": 100,
            "alienvault": 0,
            "rdap": 0,
            "crtsh": 0,
            "threatfox": 0,
            "urlhaus": 0,
        }
    )

    # Risk scoring weights
    risk_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "virustotal": 0.35,
            "abuseipdb": 0.25,
            "threatfox": 0.20,
            "urlhaus": 0.20,
        }
    )

    # Enabled APIs
    enabled_apis: dict[str, bool] = Field(
        default_factory=lambda: {
            "virustotal": True,
            "urlscan": True,
            "abuseipdb": True,
            "shodan": True,
            "whoisxml": False,
            "triage": False,
            "alienvault": False,
            "rdap": True,
            "crtsh": True,
            "threatfox": True,
            "urlhaus": True,
        }
    )

    # Logging
    log_level: str = "INFO"

    @field_validator("risk_weights")
    @classmethod
    def validate_risk_weights(cls, v: dict[str, float]) -> dict[str, float]:
        """Validate that risk weights sum to approximately 1.0."""
        total = sum(v.values())
        if not (0.99 <= total <= 1.01):
            # Normalize weights
            return {k: val / total for k, val in v.items()}
        return v

    def get_api_key(self, api_name: str) -> Optional[str]:
        """Get API key by name."""
        key_attr = f"{api_name.lower()}_api_key"
        return getattr(self, key_attr, None)

    def is_api_enabled(self, api_name: str) -> bool:
        """Check if an API is enabled."""
        return self.enabled_apis.get(api_name.lower(), False)

    def has_api_key(self, api_name: str) -> bool:
        """Check if an API key is configured."""
        key = self.get_api_key(api_name)
        return key is not None and len(key) > 0

    def get_rate_limit(self, api_name: str) -> int:
        """Get rate limit for an API (requests per minute)."""
        return self.rate_limits.get(api_name.lower(), 60)

    def get_cache_ttl(self, api_name: str) -> int:
        """Get cache TTL for an API in hours."""
        return self.ttl_overrides.get(
            api_name.lower(),
            self.cache.default_ttl_hours
        )

    def get_api_tier(self, api_name: str) -> str:
        """Get the tier for an API (free or premium)."""
        return self.api_tiers.get(api_name.lower(), "free")

    def is_premium(self, api_name: str) -> bool:
        """Check if an API is configured as premium tier."""
        return self.get_api_tier(api_name) == "premium"

    def get_daily_quota(self, api_name: str) -> int:
        """Get daily quota for an API. Returns 0 for unlimited."""
        return self.daily_quotas.get(api_name.lower(), 0)

    def get_cache_path(self) -> Path:
        """Get the full path to the cache database."""
        project_root = find_project_root()
        return project_root / self.cache.database_path

    @classmethod
    def from_yaml(cls, config_path: Optional[Path] = None) -> "Settings":
        """Create settings from YAML config file merged with environment."""
        yaml_config = load_yaml_config(config_path)

        # Flatten nested YAML config for pydantic
        flat_config: dict[str, Any] = {}

        if "cache" in yaml_config:
            flat_config["cache"] = CacheSettings(**yaml_config["cache"])

        if "reports" in yaml_config:
            flat_config["reports"] = ReportSettings(**yaml_config["reports"])

        if "rate_limits" in yaml_config:
            flat_config["rate_limits"] = yaml_config["rate_limits"]

        if "ttl_overrides" in yaml_config:
            flat_config["ttl_overrides"] = yaml_config["ttl_overrides"]

        if "risk_weights" in yaml_config:
            flat_config["risk_weights"] = yaml_config["risk_weights"]

        if "enabled_apis" in yaml_config:
            flat_config["enabled_apis"] = yaml_config["enabled_apis"]

        if "api_tiers" in yaml_config:
            flat_config["api_tiers"] = yaml_config["api_tiers"]

        if "daily_quotas" in yaml_config:
            flat_config["daily_quotas"] = yaml_config["daily_quotas"]

        if "logging" in yaml_config:
            flat_config["log_level"] = yaml_config["logging"].get("level", "INFO")

        return cls(**flat_config)


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings.from_yaml()


def reload_settings() -> Settings:
    """Reload settings (clears cache)."""
    get_settings.cache_clear()
    return get_settings()
