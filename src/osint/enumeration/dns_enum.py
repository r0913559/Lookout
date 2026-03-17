"""Async DNS-based subdomain enumeration.

Cross-platform (Windows/Linux/macOS) — uses only Python standard library
and asyncio for parallel resolution. No external tools required.
"""

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from osint.core.config import find_project_root

logger = logging.getLogger("osint.enumeration.dns")


@dataclass
class ResolvedSubdomain:
    """A subdomain that successfully resolved."""

    subdomain: str
    ips: list[str] = field(default_factory=list)
    source: str = "dns"  # dns, crtsh, both
    cname: Optional[str] = None


@dataclass
class EnumerationResult:
    """Result of a subdomain enumeration."""

    domain: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Found subdomains
    resolved: list[ResolvedSubdomain] = field(default_factory=list)

    # Statistics
    total_checked: int = 0
    total_found: int = 0
    duration_seconds: float = 0.0

    # From certificate transparency (crt.sh)
    crtsh_subdomains: list[str] = field(default_factory=list)

    # Combined unique subdomains
    @property
    def all_subdomains(self) -> list[str]:
        """All unique subdomains found (DNS + crt.sh)."""
        seen = set()
        result = []
        for r in self.resolved:
            lower = r.subdomain.lower()
            if lower not in seen:
                seen.add(lower)
                result.append(r.subdomain)
        return sorted(result)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "timestamp": self.timestamp.isoformat(),
            "total_checked": self.total_checked,
            "total_found": self.total_found,
            "duration_seconds": self.duration_seconds,
            "subdomains": [
                {
                    "name": r.subdomain,
                    "ips": r.ips,
                    "source": r.source,
                    "cname": r.cname,
                }
                for r in self.resolved
            ],
        }


def load_wordlist(path: Optional[Path] = None) -> list[str]:
    """Load subdomain prefixes from wordlist file.

    Args:
        path: Path to wordlist. Defaults to data/subdomains.txt

    Returns:
        List of subdomain prefixes.
    """
    if path is None:
        path = find_project_root() / "data" / "subdomains.txt"

    if not path.exists():
        logger.warning(f"Wordlist not found at {path}, using minimal default")
        return _default_wordlist()

    prefixes = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            prefixes.append(line.lower())

    logger.info(f"Loaded {len(prefixes)} prefixes from {path}")
    return prefixes


def _default_wordlist() -> list[str]:
    """Minimal fallback wordlist."""
    return [
        "www", "mail", "ftp", "admin", "cpanel", "webmail", "login",
        "portal", "secure", "api", "app", "dev", "staging", "test",
        "vpn", "remote", "panel", "dashboard", "billing", "pay",
        "verify", "account", "support", "help", "shop", "blog",
    ]


async def _resolve_one(
    fqdn: str,
    semaphore: asyncio.Semaphore,
    timeout: float = 3.0,
) -> Optional[ResolvedSubdomain]:
    """Resolve a single FQDN. Returns None if it doesn't resolve.

    Uses getaddrinfo which works on all platforms including Windows.
    """
    async with semaphore:
        loop = asyncio.get_event_loop()
        try:
            results = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM),
                ),
                timeout=timeout,
            )
            ips = sorted(set(r[4][0] for r in results))
            return ResolvedSubdomain(subdomain=fqdn, ips=ips, source="dns")
        except (socket.gaierror, asyncio.TimeoutError, OSError):
            return None


async def enumerate_subdomains(
    domain: str,
    wordlist_path: Optional[Path] = None,
    concurrency: int = 50,
    timeout: float = 3.0,
    crtsh_subdomains: Optional[list[str]] = None,
    progress_callback=None,
) -> EnumerationResult:
    """Enumerate subdomains for a domain using DNS resolution.

    Args:
        domain: Target domain (e.g. "example.com")
        wordlist_path: Path to wordlist file
        concurrency: Max parallel DNS queries
        timeout: Timeout per DNS query in seconds
        crtsh_subdomains: Subdomains already found via crt.sh (will be merged)
        progress_callback: Optional callback(checked, total) for progress

    Returns:
        EnumerationResult with all found subdomains.
    """
    start = datetime.utcnow()

    # Load wordlist
    prefixes = load_wordlist(wordlist_path)

    # Build FQDN list from wordlist
    fqdns_to_check = set()
    for prefix in prefixes:
        fqdn = f"{prefix}.{domain}".lower()
        fqdns_to_check.add(fqdn)

    # Add crt.sh subdomains that aren't in the wordlist
    crtsh_set = set()
    if crtsh_subdomains:
        for sub in crtsh_subdomains:
            sub_lower = sub.lower().rstrip(".")
            if sub_lower.startswith("*."):
                continue
            crtsh_set.add(sub_lower)
            fqdns_to_check.add(sub_lower)

    total = len(fqdns_to_check)
    fqdns_sorted = sorted(fqdns_to_check)

    # Resolve in parallel
    semaphore = asyncio.Semaphore(concurrency)
    resolved: list[ResolvedSubdomain] = []
    checked = 0

    # Process in batches to allow progress updates
    batch_size = concurrency * 2
    for i in range(0, len(fqdns_sorted), batch_size):
        batch = fqdns_sorted[i : i + batch_size]
        tasks = [_resolve_one(fqdn, semaphore, timeout) for fqdn in batch]
        results = await asyncio.gather(*tasks)

        for fqdn, result in zip(batch, results):
            if result is not None:
                # Tag source
                if fqdn in crtsh_set:
                    result.source = "both" if fqdn.split(".")[0] in [p for p in prefixes] else "crtsh"
                resolved.append(result)

        checked += len(batch)
        if progress_callback:
            progress_callback(checked, total)

    # Sort by subdomain name
    resolved.sort(key=lambda r: r.subdomain)

    duration = (datetime.utcnow() - start).total_seconds()

    return EnumerationResult(
        domain=domain,
        total_checked=total,
        total_found=len(resolved),
        duration_seconds=duration,
        resolved=resolved,
        crtsh_subdomains=list(crtsh_set),
    )
