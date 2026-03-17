"""Tests for indicator type detection."""

import pytest

from osint.core.constants import IndicatorType
from osint.core.exceptions import DetectionError
from osint.detection.indicator_type import IndicatorDetector, detect_indicator_type


class TestIndicatorDetector:
    """Tests for the IndicatorDetector class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = IndicatorDetector()

    # Domain tests
    def test_detect_domain_simple(self):
        """Test detection of simple domain."""
        assert self.detector.detect("google.com") == IndicatorType.DOMAIN

    def test_detect_domain_subdomain(self):
        """Test detection of domain with subdomain."""
        assert self.detector.detect("www.google.com") == IndicatorType.DOMAIN
        assert self.detector.detect("mail.google.com") == IndicatorType.DOMAIN

    def test_detect_domain_with_trailing_dot(self):
        """Test detection of domain with trailing dot."""
        assert self.detector.detect("google.com.") == IndicatorType.DOMAIN

    def test_detect_domain_various_tlds(self):
        """Test detection of domains with various TLDs."""
        assert self.detector.detect("example.co.uk") == IndicatorType.DOMAIN
        assert self.detector.detect("example.io") == IndicatorType.DOMAIN
        assert self.detector.detect("example.xyz") == IndicatorType.DOMAIN

    # IP tests
    def test_detect_ipv4(self):
        """Test detection of IPv4 addresses."""
        assert self.detector.detect("192.168.1.1") == IndicatorType.IPV4
        assert self.detector.detect("8.8.8.8") == IndicatorType.IPV4
        assert self.detector.detect("255.255.255.255") == IndicatorType.IPV4

    def test_detect_ipv6(self):
        """Test detection of IPv6 addresses."""
        assert self.detector.detect("::1") == IndicatorType.IPV6
        assert self.detector.detect("2001:db8::1") == IndicatorType.IPV6
        assert self.detector.detect("fe80::1") == IndicatorType.IPV6

    # Hash tests
    def test_detect_md5(self):
        """Test detection of MD5 hashes."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        assert self.detector.detect(md5) == IndicatorType.MD5

    def test_detect_sha1(self):
        """Test detection of SHA1 hashes."""
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert self.detector.detect(sha1) == IndicatorType.SHA1

    def test_detect_sha256(self):
        """Test detection of SHA256 hashes."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert self.detector.detect(sha256) == IndicatorType.SHA256

    def test_detect_hash_uppercase(self):
        """Test detection of uppercase hashes."""
        md5_upper = "D41D8CD98F00B204E9800998ECF8427E"
        assert self.detector.detect(md5_upper) == IndicatorType.MD5

    # URL tests
    def test_detect_url_http(self):
        """Test detection of HTTP URLs."""
        assert self.detector.detect("http://example.com") == IndicatorType.URL

    def test_detect_url_https(self):
        """Test detection of HTTPS URLs."""
        assert self.detector.detect("https://example.com") == IndicatorType.URL

    def test_detect_url_with_path(self):
        """Test detection of URLs with paths."""
        assert self.detector.detect("https://example.com/path/to/page") == IndicatorType.URL

    def test_detect_url_with_query(self):
        """Test detection of URLs with query strings."""
        assert self.detector.detect("https://example.com/search?q=test") == IndicatorType.URL

    def test_detect_url_with_port(self):
        """Test detection of URLs with ports."""
        assert self.detector.detect("http://example.com:8080") == IndicatorType.URL

    # Email tests
    def test_detect_email(self):
        """Test detection of email addresses."""
        assert self.detector.detect("user@example.com") == IndicatorType.EMAIL
        assert self.detector.detect("user.name@example.com") == IndicatorType.EMAIL

    # Error cases
    def test_detect_invalid_raises_error(self):
        """Test that invalid input raises DetectionError."""
        with pytest.raises(DetectionError):
            self.detector.detect("not_a_valid_indicator")

    def test_detect_empty_raises_error(self):
        """Test that empty input raises DetectionError."""
        with pytest.raises(DetectionError):
            self.detector.detect("")

    # Validation tests
    def test_is_valid_correct_type(self):
        """Test is_valid with correct type."""
        assert self.detector.is_valid("google.com", IndicatorType.DOMAIN)
        assert self.detector.is_valid("8.8.8.8", IndicatorType.IPV4)

    def test_is_valid_wrong_type(self):
        """Test is_valid with wrong type."""
        assert not self.detector.is_valid("google.com", IndicatorType.IPV4)
        assert not self.detector.is_valid("8.8.8.8", IndicatorType.DOMAIN)


class TestDetectIndicatorTypeFunction:
    """Tests for the detect_indicator_type convenience function."""

    def test_detect_domain(self):
        """Test detection of domain via function."""
        assert detect_indicator_type("example.com") == IndicatorType.DOMAIN

    def test_detect_ip(self):
        """Test detection of IP via function."""
        assert detect_indicator_type("1.2.3.4") == IndicatorType.IPV4

    def test_detect_hash(self):
        """Test detection of hash via function."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_indicator_type(sha256) == IndicatorType.SHA256
