"""Rate limiting utilities."""

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Optional


class RateLimiter(ABC):
    """Abstract base class for rate limiters."""

    @abstractmethod
    async def acquire(self) -> None:
        """Acquire permission to make a request. Blocks if rate limited."""
        pass

    @abstractmethod
    def try_acquire(self) -> bool:
        """Try to acquire permission without blocking. Returns False if rate limited."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset the rate limiter state."""
        pass


class TokenBucketRateLimiter(RateLimiter):
    """
    Token bucket rate limiter.

    Allows bursts up to the bucket capacity, then enforces
    the sustained rate.
    """

    def __init__(
        self,
        rate: float,  # Requests per minute
        burst: Optional[int] = None,  # Max burst size
    ):
        """
        Initialize the rate limiter.

        Args:
            rate: Maximum requests per minute
            burst: Maximum burst size (defaults to rate)
        """
        self.rate = rate / 60.0  # Convert to per-second
        self.burst = burst if burst is not None else max(1, int(rate / 10))
        self.tokens = float(self.burst)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_update = now

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            self._refill()

            if self.tokens >= 1:
                self.tokens -= 1
                return

            # Calculate wait time for next token
            wait_time = (1 - self.tokens) / self.rate
            await asyncio.sleep(wait_time)

            self._refill()
            self.tokens -= 1

    def try_acquire(self) -> bool:
        """Try to acquire a token without waiting."""
        self._refill()

        if self.tokens >= 1:
            self.tokens -= 1
            return True

        return False

    def reset(self) -> None:
        """Reset the bucket to full capacity."""
        self.tokens = float(self.burst)
        self.last_update = time.monotonic()

    @property
    def available_tokens(self) -> int:
        """Get the current number of available tokens."""
        self._refill()
        return int(self.tokens)

    @property
    def wait_time(self) -> float:
        """Get estimated wait time for next token in seconds."""
        self._refill()
        if self.tokens >= 1:
            return 0.0
        return (1 - self.tokens) / self.rate


class SlidingWindowRateLimiter(RateLimiter):
    """
    Sliding window rate limiter.

    Tracks individual request timestamps for precise rate limiting.
    Better for APIs with strict per-period limits.
    """

    def __init__(
        self,
        max_requests: int,
        window_seconds: float = 60.0,
    ):
        """
        Initialize the rate limiter.

        Args:
            max_requests: Maximum requests allowed in the window
            window_seconds: Window size in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: list[float] = []
        self._lock = asyncio.Lock()

    def _cleanup(self) -> None:
        """Remove expired timestamps."""
        cutoff = time.monotonic() - self.window_seconds
        self.requests = [t for t in self.requests if t > cutoff]

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        async with self._lock:
            self._cleanup()

            if len(self.requests) < self.max_requests:
                self.requests.append(time.monotonic())
                return

            # Wait until oldest request expires
            oldest = self.requests[0]
            wait_time = oldest + self.window_seconds - time.monotonic()

            if wait_time > 0:
                await asyncio.sleep(wait_time)

            self._cleanup()
            self.requests.append(time.monotonic())

    def try_acquire(self) -> bool:
        """Try to acquire permission without waiting."""
        self._cleanup()

        if len(self.requests) < self.max_requests:
            self.requests.append(time.monotonic())
            return True

        return False

    def reset(self) -> None:
        """Clear all tracked requests."""
        self.requests.clear()

    @property
    def remaining_requests(self) -> int:
        """Get remaining requests in current window."""
        self._cleanup()
        return max(0, self.max_requests - len(self.requests))

    @property
    def wait_time(self) -> float:
        """Get estimated wait time for next request in seconds."""
        self._cleanup()

        if len(self.requests) < self.max_requests:
            return 0.0

        oldest = self.requests[0]
        return max(0.0, oldest + self.window_seconds - time.monotonic())
