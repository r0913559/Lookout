"""Indicator of Compromise (IOC) models."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from osint.core.constants import IndicatorType


class BaseIndicator(BaseModel):
    """Base class for all indicators."""

    value: str
    indicator_type: IndicatorType
    created_at: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list)
    notes: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.indicator_type.value}:{self.value}"

    def __hash__(self) -> int:
        return hash((self.indicator_type, self.value.lower()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseIndicator):
            return False
        return (
            self.indicator_type == other.indicator_type
            and self.value.lower() == other.value.lower()
        )


class DomainIndicator(BaseIndicator):
    """Domain name indicator."""

    indicator_type: IndicatorType = IndicatorType.DOMAIN

    @field_validator("value")
    @classmethod
    def normalize_domain(cls, v: str) -> str:
        """Normalize domain to lowercase without trailing dot."""
        return v.lower().rstrip(".")


class IPIndicator(BaseIndicator):
    """IP address indicator (IPv4 or IPv6)."""

    indicator_type: IndicatorType = IndicatorType.IPV4
    asn: Optional[str] = None
    as_name: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None

    @field_validator("value")
    @classmethod
    def normalize_ip(cls, v: str) -> str:
        """Normalize IP address."""
        import ipaddress

        try:
            ip = ipaddress.ip_address(v)
            return str(ip)
        except ValueError:
            return v


class HashIndicator(BaseIndicator):
    """File hash indicator (MD5, SHA1, SHA256)."""

    indicator_type: IndicatorType = IndicatorType.SHA256
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None

    @field_validator("value")
    @classmethod
    def normalize_hash(cls, v: str) -> str:
        """Normalize hash to lowercase."""
        return v.lower()

    @field_validator("indicator_type")
    @classmethod
    def validate_hash_type(cls, v: IndicatorType) -> IndicatorType:
        """Ensure indicator type is a hash type."""
        if not v.is_hash:
            raise ValueError(f"Invalid hash type: {v}")
        return v


class URLIndicator(BaseIndicator):
    """URL indicator."""

    indicator_type: IndicatorType = IndicatorType.URL
    scheme: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None

    @field_validator("value")
    @classmethod
    def normalize_url(cls, v: str) -> str:
        """Normalize URL."""
        from urllib.parse import urlparse, urlunparse

        try:
            parsed = urlparse(v)
            # Ensure scheme
            if not parsed.scheme:
                parsed = urlparse(f"http://{v}")
            return urlunparse(parsed)
        except Exception:
            return v

    def model_post_init(self, __context: object) -> None:
        """Extract URL components after initialization."""
        from urllib.parse import urlparse

        try:
            parsed = urlparse(self.value)
            self.scheme = parsed.scheme or None
            self.domain = parsed.netloc or None
            self.path = parsed.path or None
            self.query = parsed.query or None
        except Exception:
            pass


class EmailIndicator(BaseIndicator):
    """Email address indicator."""

    indicator_type: IndicatorType = IndicatorType.EMAIL
    local_part: Optional[str] = None
    domain_part: Optional[str] = None

    @field_validator("value")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        """Normalize email to lowercase."""
        return v.lower()

    def model_post_init(self, __context: object) -> None:
        """Extract email components after initialization."""
        if "@" in self.value:
            parts = self.value.split("@", 1)
            self.local_part = parts[0]
            self.domain_part = parts[1] if len(parts) > 1 else None


def create_indicator(value: str, indicator_type: IndicatorType) -> BaseIndicator:
    """Factory function to create the appropriate indicator type."""
    type_to_class = {
        IndicatorType.DOMAIN: DomainIndicator,
        IndicatorType.IPV4: IPIndicator,
        IndicatorType.IPV6: IPIndicator,
        IndicatorType.MD5: HashIndicator,
        IndicatorType.SHA1: HashIndicator,
        IndicatorType.SHA256: HashIndicator,
        IndicatorType.URL: URLIndicator,
        IndicatorType.EMAIL: EmailIndicator,
    }

    cls = type_to_class.get(indicator_type, BaseIndicator)
    return cls(value=value, indicator_type=indicator_type)
