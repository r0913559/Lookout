"""Auto-detection of indicator types."""

import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

from osint.core.constants import IndicatorType
from osint.core.exceptions import DetectionError


class IndicatorDetector:
    """Detect the type of an indicator value."""

    # Hash patterns
    MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

    # URL pattern (must start with http:// or https://)
    URL_PATTERN = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain
        r"localhost|"  # localhost
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # or IP
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",  # path
        re.IGNORECASE,
    )

    # Domain pattern (more restrictive)
    DOMAIN_PATTERN = re.compile(
        r"^(?!-)"  # Can't start with hyphen
        r"(?:[A-Z0-9-]{1,63}\.)*"  # Subdomains
        r"[A-Z0-9][A-Z0-9-]{0,61}[A-Z0-9]"  # Domain name
        r"\.[A-Z]{2,}$",  # TLD
        re.IGNORECASE,
    )

    # Email pattern
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )

    # Common TLDs for validation
    COMMON_TLDS = {
        "com", "net", "org", "edu", "gov", "mil", "int",
        "co", "io", "ai", "app", "dev", "cloud",
        "uk", "de", "fr", "nl", "be", "ru", "cn", "jp", "au",
        "info", "biz", "name", "pro", "museum", "coop", "aero",
        "xyz", "online", "site", "tech", "store", "blog",
    }

    def detect(self, value: str) -> IndicatorType:
        """
        Detect the indicator type for a given value.

        Args:
            value: The indicator value to classify

        Returns:
            The detected IndicatorType

        Raises:
            DetectionError: If the type cannot be determined
        """
        if not value or not isinstance(value, str):
            raise DetectionError(str(value), "Empty or invalid value")

        value = value.strip()

        # Try each detection method in order of specificity
        detected = (
            self._detect_hash(value)
            or self._detect_url(value)
            or self._detect_email(value)
            or self._detect_ip(value)
            or self._detect_domain(value)
        )

        if detected is None:
            raise DetectionError(value)

        return detected

    def _detect_hash(self, value: str) -> Optional[IndicatorType]:
        """Detect if value is a hash (MD5, SHA1, SHA256)."""
        # Check patterns in order of length
        if self.SHA256_PATTERN.match(value):
            return IndicatorType.SHA256
        if self.SHA1_PATTERN.match(value):
            return IndicatorType.SHA1
        if self.MD5_PATTERN.match(value):
            return IndicatorType.MD5
        return None

    def _detect_url(self, value: str) -> Optional[IndicatorType]:
        """Detect if value is a URL."""
        # Must have scheme
        if not value.lower().startswith(("http://", "https://")):
            return None

        try:
            parsed = urlparse(value)
            # Must have netloc (domain/IP)
            if parsed.netloc:
                return IndicatorType.URL
        except Exception:
            pass

        return None

    def _detect_email(self, value: str) -> Optional[IndicatorType]:
        """Detect if value is an email address."""
        if "@" in value and self.EMAIL_PATTERN.match(value):
            return IndicatorType.EMAIL
        return None

    def _detect_ip(self, value: str) -> Optional[IndicatorType]:
        """Detect if value is an IP address (IPv4 or IPv6)."""
        try:
            ip = ipaddress.ip_address(value)
            if isinstance(ip, ipaddress.IPv4Address):
                return IndicatorType.IPV4
            elif isinstance(ip, ipaddress.IPv6Address):
                return IndicatorType.IPV6
        except ValueError:
            pass
        return None

    def _detect_domain(self, value: str) -> Optional[IndicatorType]:
        """Detect if value is a domain name."""
        # Remove trailing dot if present
        value = value.rstrip(".")

        # Basic validation
        if not value or len(value) > 253:
            return None

        # Can't be all numeric (would be IP)
        if value.replace(".", "").isdigit():
            return None

        # Must have at least one dot
        if "." not in value:
            return None

        # Check pattern
        if self.DOMAIN_PATTERN.match(value):
            # Verify TLD exists
            tld = value.split(".")[-1].lower()
            # Allow any TLD of 2+ chars (covers all country codes and new gTLDs)
            if len(tld) >= 2:
                return IndicatorType.DOMAIN

        return None

    def is_valid(self, value: str, expected_type: IndicatorType) -> bool:
        """
        Validate that a value matches an expected indicator type.

        Args:
            value: The value to validate
            expected_type: The expected indicator type

        Returns:
            True if the value matches the expected type
        """
        try:
            detected = self.detect(value)
            return detected == expected_type
        except DetectionError:
            return False

    def extract_domain_from_url(self, url: str) -> Optional[str]:
        """Extract domain from a URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.split(":")[0] if parsed.netloc else None
        except Exception:
            return None


# Singleton instance
_detector = IndicatorDetector()


def detect_indicator_type(value: str) -> IndicatorType:
    """
    Convenience function to detect indicator type.

    Args:
        value: The indicator value to classify

    Returns:
        The detected IndicatorType

    Raises:
        DetectionError: If the type cannot be determined
    """
    return _detector.detect(value)
