"""Base API client with rate limiting and common functionality."""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Generic, Optional, TypeVar

import aiohttp

from osint.core.config import Settings, get_settings
from osint.core.constants import APISource, IndicatorType
from osint.core.exceptions import APIError, RateLimitError
from osint.models.results import APIResult
from osint.utils.rate_limiter import TokenBucketRateLimiter

T = TypeVar("T", bound=APIResult)


class BaseAPIClient(ABC, Generic[T]):
    """
    Abstract base class for API clients.

    Provides common functionality like rate limiting, error handling,
    and HTTP request management.
    """

    name: str = "base"
    base_url: str = ""
    requires_auth: bool = True
    source: APISource

    def __init__(
        self,
        settings: Optional[Settings] = None,
        session: Optional[aiohttp.ClientSession] = None,
    ):
        """
        Initialize the API client.

        Args:
            settings: Application settings (uses default if not provided)
            session: Shared aiohttp session (creates own if not provided)
        """
        self.settings = settings or get_settings()
        self._session = session
        self._owns_session = session is None
        self.logger = logging.getLogger(f"osint.clients.{self.name}")

        # Initialize rate limiter
        rate_limit = self.settings.get_rate_limit(self.name)
        self.rate_limiter = TokenBucketRateLimiter(rate=rate_limit)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers=self._get_default_headers(),
            )
            self._owns_session = True
        return self._session

    def _get_default_headers(self) -> dict[str, str]:
        """Get default headers for requests."""
        return {
            "User-Agent": "OSINT-Tool/0.1.0",
            "Accept": "application/json",
        }

    def _get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers. Override in subclasses."""
        return {}

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict[str, Any]] = None,
        json_data: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """
        Make an HTTP request with rate limiting and error handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (appended to base_url)
            params: Query parameters
            json_data: JSON body data
            headers: Additional headers
            timeout: Request timeout in seconds

        Returns:
            Parsed JSON response

        Raises:
            APIError: On API errors
            RateLimitError: When rate limited
        """
        # Apply rate limiting
        await self.rate_limiter.acquire()

        session = await self._get_session()
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"

        # Merge headers
        request_headers = self._get_default_headers()
        request_headers.update(self._get_auth_headers())
        if headers:
            request_headers.update(headers)

        # Set timeout
        request_timeout = aiohttp.ClientTimeout(total=timeout or 30)

        try:
            self.logger.debug(f"Requesting {method} {url}")

            async with session.request(
                method,
                url,
                params=params,
                json=json_data,
                headers=request_headers,
                timeout=request_timeout,
            ) as response:
                response_text = await response.text()

                # Handle rate limiting
                if response.status == 429:
                    retry_after = response.headers.get("Retry-After")
                    raise RateLimitError(
                        self.name,
                        retry_after=int(retry_after) if retry_after else None,
                    )

                # Handle errors
                if response.status >= 400:
                    raise APIError(
                        f"API request failed: {response.status}",
                        api_name=self.name,
                        status_code=response.status,
                        response_body=response_text[:500],
                    )

                # Parse JSON
                try:
                    return await response.json()
                except Exception:
                    # Some APIs return empty responses on success
                    if response.status == 200:
                        return {}
                    raise APIError(
                        "Invalid JSON response",
                        api_name=self.name,
                        status_code=response.status,
                        response_body=response_text[:500],
                    )

        except aiohttp.ClientError as e:
            raise APIError(
                f"Request failed: {str(e)}",
                api_name=self.name,
            )

    async def close(self) -> None:
        """Close the HTTP session if we own it."""
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> "BaseAPIClient[T]":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    def is_available(self) -> bool:
        """Check if this client is available (enabled and configured)."""
        if not self.settings.is_api_enabled(self.name):
            return False
        if self.requires_auth and not self.settings.has_api_key(self.name):
            return False
        return True

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """
        Check if this client supports a given indicator type.
        Override in subclasses for specific support.
        """
        return True

    @abstractmethod
    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[T]:
        """
        Perform a lookup for an indicator.

        Args:
            value: The indicator value
            indicator_type: The type of indicator

        Returns:
            API result or None if not found
        """
        pass

    async def lookup_domain(self, domain: str) -> Optional[T]:
        """Lookup a domain."""
        return await self.lookup(domain, IndicatorType.DOMAIN)

    async def lookup_ip(self, ip: str) -> Optional[T]:
        """Lookup an IP address."""
        # Try to determine IPv4 vs IPv6
        if ":" in ip:
            return await self.lookup(ip, IndicatorType.IPV6)
        return await self.lookup(ip, IndicatorType.IPV4)

    async def lookup_hash(
        self,
        hash_value: str,
        hash_type: Optional[IndicatorType] = None,
    ) -> Optional[T]:
        """Lookup a file hash."""
        # Auto-detect hash type if not specified
        if hash_type is None:
            length = len(hash_value)
            if length == 32:
                hash_type = IndicatorType.MD5
            elif length == 40:
                hash_type = IndicatorType.SHA1
            elif length == 64:
                hash_type = IndicatorType.SHA256
            else:
                hash_type = IndicatorType.SHA256  # Default

        return await self.lookup(hash_value, hash_type)

    async def lookup_url(self, url: str) -> Optional[T]:
        """Lookup a URL."""
        return await self.lookup(url, IndicatorType.URL)
