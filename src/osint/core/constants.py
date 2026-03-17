"""Constants and enumerations for the OSINT tool."""

from enum import Enum, auto


class IndicatorType(str, Enum):
    """Types of indicators of compromise (IOCs)."""

    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"
    EMAIL = "email"

    def __str__(self) -> str:
        return self.value

    @property
    def is_hash(self) -> bool:
        """Check if this indicator type is a hash."""
        return self in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256)

    @property
    def is_ip(self) -> bool:
        """Check if this indicator type is an IP address."""
        return self in (IndicatorType.IPV4, IndicatorType.IPV6)


class RiskLevel(str, Enum):
    """Risk classification levels."""

    UNKNOWN = "unknown"
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """Convert a 0-100 score to a risk level."""
        if score < 0:
            return cls.UNKNOWN
        elif score < 10:
            return cls.CLEAN
        elif score < 30:
            return cls.LOW
        elif score < 60:
            return cls.MEDIUM
        elif score < 85:
            return cls.HIGH
        else:
            return cls.CRITICAL


class APISource(str, Enum):
    """Available API data sources."""

    VIRUSTOTAL = "virustotal"
    URLSCAN = "urlscan"
    ABUSEIPDB = "abuseipdb"
    SHODAN = "shodan"
    WHOISXML = "whoisxml"
    TRIAGE = "triage"
    ALIENVAULT = "alienvault"
    RDAP = "rdap"
    CRTSH = "crtsh"
    THREATFOX = "threatfox"
    URLHAUS = "urlhaus"

    def __str__(self) -> str:
        return self.value

    @property
    def requires_auth(self) -> bool:
        """Check if this API requires authentication."""
        return self not in (
            APISource.RDAP,
            APISource.CRTSH,
            APISource.THREATFOX,
            APISource.URLHAUS,
        )


class OutputFormat(str, Enum):
    """Output format options."""

    JSON = "json"
    MARKDOWN = "markdown"
    TABLE = "table"

    def __str__(self) -> str:
        return self.value


# Default rate limits (requests per minute)
DEFAULT_RATE_LIMITS: dict[str, int] = {
    "virustotal": 4,
    "urlscan": 100,
    "shodan": 60,
    "abuseipdb": 70,  # ~1000/day converted to per-minute
    "whoisxml": 30,
    "triage": 60,
    "alienvault": 60,
    "rdap": 60,
    "crtsh": 30,
    "threatfox": 60,
    "urlhaus": 60,
}

# Default cache TTL in hours
DEFAULT_CACHE_TTL_HOURS: int = 24
