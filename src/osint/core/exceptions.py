"""Exception hierarchy for the OSINT tool."""

from typing import Optional


class OSINTError(Exception):
    """Base exception for all OSINT tool errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class APIError(OSINTError):
    """Error communicating with an external API."""

    def __init__(
        self,
        message: str,
        api_name: str,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
    ):
        super().__init__(
            message,
            details={
                "api_name": api_name,
                "status_code": status_code,
                "response_body": response_body,
            },
        )
        self.api_name = api_name
        self.status_code = status_code
        self.response_body = response_body


class RateLimitError(APIError):
    """Rate limit exceeded for an API."""

    def __init__(
        self,
        api_name: str,
        retry_after: Optional[int] = None,
    ):
        message = f"Rate limit exceeded for {api_name}"
        if retry_after:
            message += f", retry after {retry_after} seconds"
        super().__init__(message, api_name, status_code=429)
        self.retry_after = retry_after


class ConfigurationError(OSINTError):
    """Error in configuration (missing keys, invalid values)."""

    def __init__(self, message: str, config_key: Optional[str] = None):
        super().__init__(message, details={"config_key": config_key})
        self.config_key = config_key


class CacheError(OSINTError):
    """Error with the cache system."""

    pass


class DetectionError(OSINTError):
    """Error detecting indicator type."""

    def __init__(self, value: str, message: Optional[str] = None):
        msg = message or f"Could not detect indicator type for: {value}"
        super().__init__(msg, details={"value": value})
        self.value = value


class ValidationError(OSINTError):
    """Error validating input data."""

    def __init__(self, message: str, field: Optional[str] = None):
        super().__init__(message, details={"field": field})
        self.field = field
