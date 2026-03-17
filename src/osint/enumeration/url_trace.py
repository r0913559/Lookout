"""Async URL redirect chain tracer.

Follows HTTP redirect chains hop-by-hop, recording status codes, resolved IPs,
and response headers at each step. Useful for uncovering the final destination
behind URL shorteners, cloakers, and phishing delivery chains.

Cross-platform — uses aiohttp for async HTTP requests and socket for DNS resolution.
"""

import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp

logger = logging.getLogger("osint.enumeration.url_trace")

# Headers collected at each hop if present
INTERESTING_HEADERS = (
    "server",
    "x-powered-by",
    "via",
    "x-forwarded-for",
    "cf-ray",
    "x-cache",
    "content-type",
    "x-frame-options",
    "set-cookie",
    "x-redirect-by",
)

# Browser-like User-Agent to avoid trivial bot blocks
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

# HTTP status codes that indicate a redirect
_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass
class RedirectHop:
    """A single hop in a redirect chain."""

    url: str
    status_code: int
    location: Optional[str] = None  # Raw Location header value (redirect target)
    ip: Optional[str] = None  # Resolved IP address of the host
    server: Optional[str] = None  # Server header value
    headers: dict = field(default_factory=dict)  # Selected interesting response headers


@dataclass
class TraceResult:
    """Result of tracing a URL's redirect chain."""

    original_url: str
    final_url: str
    hops: list  # list[RedirectHop]
    total_hops: int
    domains_in_chain: list  # list[str] — unique domains encountered
    ips_in_chain: list  # list[str] — unique IPs resolved
    duration_seconds: float
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict."""
        return {
            "original_url": self.original_url,
            "final_url": self.final_url,
            "total_hops": self.total_hops,
            "domains_in_chain": self.domains_in_chain,
            "ips_in_chain": self.ips_in_chain,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "hops": [
                {
                    "url": h.url,
                    "status_code": h.status_code,
                    "location": h.location,
                    "ip": h.ip,
                    "server": h.server,
                    "headers": h.headers,
                }
                for h in self.hops
            ],
        }


def _resolve_ip(hostname: str) -> Optional[str]:
    """Resolve a hostname to its first IPv4/IPv6 address.

    Uses the system resolver (non-async, but called once per hop so the
    overhead is negligible compared to the HTTP round-trip).

    Args:
        hostname: DNS hostname or IP literal.

    Returns:
        IP address string, or None if resolution fails.
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if results:
            # Prefer IPv4 (AF_INET) over IPv6 for cleaner display
            for family, _, _, _, sockaddr in results:
                if family == socket.AF_INET:
                    return sockaddr[0]
            # Fall back to first result (likely IPv6)
            return results[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


def _resolve_redirect(location: str, current_url: str) -> str:
    """Resolve a (potentially relative) Location header against the current URL.

    Args:
        location: Value of the Location response header.
        current_url: The URL of the current hop.

    Returns:
        Absolute URL string.
    """
    if location.startswith(("http://", "https://")):
        return location
    return urljoin(current_url, location)


def _extract_interesting_headers(response_headers: "aiohttp.CIMultiDictProxy") -> dict:
    """Extract a curated set of headers from an aiohttp response.

    Args:
        response_headers: The response headers mapping.

    Returns:
        Dict of header-name -> value for headers that are present.
    """
    result = {}
    for name in INTERESTING_HEADERS:
        value = response_headers.get(name)
        if value:
            result[name] = value
    return result


async def trace_url(
    url: str,
    max_redirects: int = 20,
    timeout: float = 10.0,
    proxy: Optional[str] = None,
) -> TraceResult:
    """Follow a URL's redirect chain, recording each hop.

    Makes one HTTP request per hop with allow_redirects=False so that each
    intermediate response can be inspected. Resolves the remote IP address for
    every hop via the system DNS resolver.

    Args:
        url: The starting URL to trace (must start with http:// or https://).
        max_redirects: Stop after this many hops to prevent infinite loops.
        timeout: Per-request timeout in seconds.
        proxy: Optional proxy URL (e.g. "socks5://127.0.0.1:9050").

    Returns:
        TraceResult describing every hop from the original URL to the final
        destination (or the hop where an error occurred).
    """
    start_time = time.monotonic()
    hops: list[RedirectHop] = []
    seen_urls: set[str] = set()
    error: Optional[str] = None

    # Validate scheme upfront
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return TraceResult(
            original_url=url,
            final_url=url,
            hops=[],
            total_hops=0,
            domains_in_chain=[],
            ips_in_chain=[],
            duration_seconds=0.0,
            error=f"Unsupported URL scheme: '{parsed.scheme}'. Only http and https are supported.",
        )

    connector = aiohttp.TCPConnector(ssl=False, limit=5)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    current_url = url

    try:
        async with aiohttp.ClientSession(
            connector=connector,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        ) as session:
            for hop_number in range(max_redirects + 1):
                # Guard against redirect loops
                if current_url in seen_urls:
                    error = f"Redirect loop detected at: {current_url}"
                    break
                seen_urls.add(current_url)

                # Resolve IP for this hop
                parsed_current = urlparse(current_url)
                hostname = parsed_current.hostname or ""
                ip = _resolve_ip(hostname) if hostname else None

                try:
                    async with session.get(
                        current_url,
                        timeout=client_timeout,
                        allow_redirects=False,
                        proxy=proxy,
                    ) as response:
                        status = response.status
                        location_raw = response.headers.get("Location")
                        server = response.headers.get("Server") or response.headers.get("server")
                        interesting = _extract_interesting_headers(response.headers)

                        hop = RedirectHop(
                            url=current_url,
                            status_code=status,
                            location=location_raw,
                            ip=ip,
                            server=server,
                            headers=interesting,
                        )
                        hops.append(hop)

                        logger.debug(
                            "Hop %d: %s -> %s (ip=%s)",
                            hop_number + 1,
                            current_url,
                            status,
                            ip,
                        )

                        # Decide whether to follow
                        if status in _REDIRECT_CODES and location_raw:
                            next_url = _resolve_redirect(location_raw, current_url)
                            # Validate the resolved URL has a usable scheme
                            next_parsed = urlparse(next_url)
                            if next_parsed.scheme not in ("http", "https"):
                                error = (
                                    f"Redirect to non-HTTP scheme: '{next_parsed.scheme}://...'"
                                )
                                break
                            current_url = next_url
                        else:
                            # Terminal response (200, 4xx, 5xx, or redirect without Location)
                            break

                except asyncio.TimeoutError:
                    error = f"Timeout after {timeout}s at: {current_url}"
                    # Record a partial hop so the chain is visible up to the failure
                    hops.append(RedirectHop(
                        url=current_url,
                        status_code=0,
                        ip=ip,
                        headers={"error": "timeout"},
                    ))
                    break

                except aiohttp.ClientConnectorError as exc:
                    error = f"Connection refused / unreachable: {exc.host} — {exc.strerror}"
                    hops.append(RedirectHop(
                        url=current_url,
                        status_code=0,
                        ip=ip,
                        headers={"error": str(exc)},
                    ))
                    break

                except aiohttp.ClientSSLError as exc:
                    error = f"SSL error at {current_url}: {exc}"
                    hops.append(RedirectHop(
                        url=current_url,
                        status_code=0,
                        ip=ip,
                        headers={"error": str(exc)},
                    ))
                    break

                except aiohttp.ClientError as exc:
                    error = f"HTTP client error at {current_url}: {exc}"
                    hops.append(RedirectHop(
                        url=current_url,
                        status_code=0,
                        ip=ip,
                        headers={"error": str(exc)},
                    ))
                    break

            else:
                # Loop exhausted without a terminal response
                error = f"Max redirects ({max_redirects}) reached. Chain may continue further."

    except Exception as exc:
        error = f"Unexpected error: {exc}"
        logger.exception("Unexpected error while tracing %s", url)

    # Build aggregated chain metadata
    final_url = hops[-1].url if hops else url

    # Unique domains in order of first appearance
    seen_domains: list[str] = []
    seen_domain_set: set[str] = set()
    seen_ips: list[str] = []
    seen_ip_set: set[str] = set()

    for hop in hops:
        hop_parsed = urlparse(hop.url)
        domain = hop_parsed.netloc or hop_parsed.path  # netloc covers host[:port]
        # Strip port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        if domain and domain not in seen_domain_set:
            seen_domain_set.add(domain)
            seen_domains.append(domain)

        if hop.ip and hop.ip not in seen_ip_set:
            seen_ip_set.add(hop.ip)
            seen_ips.append(hop.ip)

    duration = time.monotonic() - start_time

    return TraceResult(
        original_url=url,
        final_url=final_url,
        hops=hops,
        total_hops=len(hops),
        domains_in_chain=seen_domains,
        ips_in_chain=seen_ips,
        duration_seconds=round(duration, 3),
        error=error,
    )
