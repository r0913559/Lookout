"""Async HTTP-based path/directory enumeration.

Probes a target URL for known phishing panel paths, admin panels,
exposed config files, and other indicators of compromise.

Cross-platform — uses aiohttp for async HTTP requests.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiohttp

from osint.core.config import find_project_root

logger = logging.getLogger("osint.enumeration.path")


@dataclass
class FoundPath:
    """A path that returned an interesting HTTP response."""

    url: str
    path: str
    status_code: int
    content_length: int = 0
    content_type: str = ""
    redirect_url: Optional[str] = None
    title: Optional[str] = None
    category: str = ""  # panel, login, config, webshell, data, etc.


@dataclass
class PathEnumerationResult:
    """Result of a path enumeration."""

    target: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    found: list[FoundPath] = field(default_factory=list)

    total_checked: int = 0
    total_found: int = 0
    duration_seconds: float = 0.0
    filtered_count: int = 0
    catch_all_pattern: Optional[str] = None  # e.g. "302 -> /404.html"

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "total_checked": self.total_checked,
            "total_found": self.total_found,
            "filtered_count": self.filtered_count,
            "catch_all_pattern": self.catch_all_pattern,
            "duration_seconds": self.duration_seconds,
            "found": [
                {
                    "url": f.url,
                    "path": f.path,
                    "status_code": f.status_code,
                    "content_length": f.content_length,
                    "content_type": f.content_type,
                    "redirect_url": f.redirect_url,
                    "title": f.title,
                    "category": f.category,
                }
                for f in self.found
            ],
        }


# Path categories for display
PATH_CATEGORIES: dict[str, list[str]] = {
    "panel": [
        "panel", "control-panel", "admin", "dashboard", "cpanel",
        "panel/index.php", "panel/ctr.php", "panel/pages/main_panel.php",
        "control-panel/panel.php", "control-panel/index.php",
        "control-panel/check-action.php", "control-panel/get_user_data.php",
    ],
    "login": [
        "login", "signin", "auth", "oauth", "pages/login.php",
        "auth/login.php", "index.php", "visit.php",
    ],
    "phishing-flow": [
        "pages/sms.php", "pages/token.php", "pages/exp.php",
        "pages/approve.php", "pages/loading.php", "pages/success.php",
        "pages/check_condition.php", "auth/sms.php", "auth/token.php",
        "auth/exp.php", "auth/aprouve.php", "auth/final.php",
        "auth/wait.php", "auth/exit.php",
    ],
    "data-leak": [
        "panel/storage", "panel/get-panel/statics.json",
        "panel/get-panel/info-panel.txt", "panel/admin/admin.json",
        "panel/actions/blocked_ips.txt", "panel/graveyard", "panel/res",
        "file/file.txt", "rez.txt", "visitors.html", "error_log",
        "pages/error_log", "includes/error_log",
    ],
    "config": [
        "setting/config.php", "setting/functions.php", "config.php",
        "config(1).php", "main.php", ".env", ".git/config",
        ".htaccess", ".htpasswd", "robots.txt",
    ],
    "webshell": [
        "c99.php", "shell.php", "cmd.php", "mkcmd.php", "mkfile.php",
        "rm.php", "upload.php", "install.php", "setup.php",
        "filemanager.php", "FilesMan.php", "wso.php", "b374k.php",
        "r57.php", "p0wny.php", "alfa.php", "adminer.php",
    ],
    "anti-bot": [
        "antibots-debug/antibots.php", "botMother/botMother.php",
        "botMother/botanti.php", "botMother/bandip.php",
        "botMother/data",
    ],
    "telegram": [
        "telegramclick.php", "setting/alert-admin.php",
    ],
    "wordpress": [
        "wp-admin", "wp-login.php", "wp-config.php",
        "wp-config.php.bak", "wp-config.php~", "wp-config.php.save",
        ".wp-config.php.swp", "wp-content", "wp-includes",
        "xmlrpc.php", "wp-json/wp/v2/users", "wp-cron.php",
    ],
}


def _categorize_path(path: str) -> str:
    """Determine category for a path."""
    path_lower = path.lower().rstrip("/")
    for category, paths in PATH_CATEGORIES.items():
        if path_lower in [p.lower() for p in paths]:
            return category
    return "other"


def load_paths(path: Optional[Path] = None) -> list[str]:
    """Load paths from wordlist file.

    Args:
        path: Path to wordlist. Defaults to data/phishing-paths.txt

    Returns:
        List of paths to check.
    """
    if path is None:
        path = find_project_root() / "data" / "phishing-paths.txt"

    if not path.exists():
        logger.warning(f"Path wordlist not found at {path}, using minimal default")
        return _default_paths()

    paths = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            paths.append(line)

    logger.info(f"Loaded {len(paths)} paths from {path}")
    return paths


def _default_paths() -> list[str]:
    """Minimal fallback path list."""
    return [
        "panel", "admin", "login", "control-panel", "dashboard",
        ".env", ".git/config", "robots.txt", "wp-login.php",
        "panel/index.php", "auth/login.php", "config.php",
    ]


def _extract_title(html: str) -> Optional[str]:
    """Extract <title> from HTML response (simple regex-free parser)."""
    lower = html.lower()
    start = lower.find("<title>")
    if start == -1:
        return None
    start += 7
    end = lower.find("</title>", start)
    if end == -1:
        return None
    title = html[start:end].strip()
    return title[:100] if title else None


async def _probe_path(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    semaphore: asyncio.Semaphore,
    timeout: float = 5.0,
    proxy: Optional[str] = None,
) -> Optional[FoundPath]:
    """Probe a single path. Returns FoundPath if interesting, None otherwise."""
    async with semaphore:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
                ssl=False,
                proxy=proxy,
            ) as response:
                status = response.status

                # Skip clearly uninteresting responses
                if status in (404, 502, 503, 520, 521, 522, 523, 524):
                    return None

                content_type = response.headers.get("Content-Type", "")
                content_length = int(response.headers.get("Content-Length", 0))

                # Get redirect target
                redirect_url = None
                if status in (301, 302, 303, 307, 308):
                    redirect_url = response.headers.get("Location")

                # Try to get title for HTML responses
                title = None
                if "text/html" in content_type and status == 200:
                    try:
                        body = await response.text(encoding="utf-8", errors="ignore")
                        content_length = len(body)
                        title = _extract_title(body[:2000])
                    except Exception:
                        pass

                return FoundPath(
                    url=url,
                    path=path,
                    status_code=status,
                    content_length=content_length,
                    content_type=content_type.split(";")[0].strip(),
                    redirect_url=redirect_url,
                    title=title,
                    category=_categorize_path(path),
                )

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return None


async def enumerate_paths(
    target: str,
    wordlist_path: Optional[Path] = None,
    concurrency: int = 20,
    timeout: float = 5.0,
    schemes: Optional[list[str]] = None,
    proxy: Optional[str] = None,
) -> PathEnumerationResult:
    """Enumerate paths on a target domain/URL.

    Args:
        target: Domain or base URL (e.g. "example.com" or "https://example.com")
        wordlist_path: Path to wordlist file
        concurrency: Max parallel HTTP requests
        timeout: Timeout per request in seconds
        schemes: URL schemes to try (default: ["https", "http"])
        proxy: Proxy URL (e.g. "socks5://127.0.0.1:9050", "http://proxy:8080")

    Returns:
        PathEnumerationResult with all found paths.
    """
    start = datetime.utcnow()

    # Normalize target to base URL
    if not target.startswith(("http://", "https://")):
        schemes = schemes or ["https", "http"]
        base_urls = [f"{scheme}://{target}" for scheme in schemes]
    else:
        base_urls = [target]

    paths = load_paths(wordlist_path)
    total = len(paths) * len(base_urls)

    semaphore = asyncio.Semaphore(concurrency)
    all_found: list[FoundPath] = []

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(
        connector=connector,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/json,*/*",
        },
    ) as session:
        # Configure proxy if provided
        if proxy:
            logger.info(f"Using proxy: {proxy}")
        for base_url in base_urls:
            tasks = [
                _probe_path(session, base_url, path, semaphore, timeout, proxy)
                for path in paths
            ]
            results = await asyncio.gather(*tasks)

            for result in results:
                if result is not None:
                    all_found.append(result)

    # Deduplicate by path (keep first scheme that worked)
    seen_paths: set[str] = set()
    deduped: list[FoundPath] = []
    for f in all_found:
        if f.path.lower() not in seen_paths:
            seen_paths.add(f.path.lower())
            deduped.append(f)

    # Sort: panels and login first, then by status code
    category_order = {
        "panel": 0, "login": 1, "phishing-flow": 2, "data-leak": 3,
        "webshell": 4, "config": 5, "telegram": 6, "anti-bot": 7,
        "wordpress": 8, "other": 9,
    }
    deduped.sort(key=lambda f: (category_order.get(f.category, 99), f.status_code))

    # Detect catch-all redirect pattern: if >70% of results redirect to the
    # same URL, treat that URL as a generic catch-all and filter those results.
    filtered_count = 0
    catch_all_pattern: Optional[str] = None

    redirect_targets: dict[str, int] = {}
    for f in deduped:
        if f.redirect_url:
            redirect_targets[f.redirect_url] = redirect_targets.get(f.redirect_url, 0) + 1

    if deduped and redirect_targets:
        top_target, top_count = max(redirect_targets.items(), key=lambda kv: kv[1])
        if top_count / len(deduped) > 0.70:
            # Build a human-readable pattern label (e.g. "302 -> /404.html")
            sample_status = next(
                f.status_code for f in deduped if f.redirect_url == top_target
            )
            catch_all_pattern = f"{sample_status} -> {top_target}"
            logger.info(
                f"Catch-all redirect detected: {catch_all_pattern} "
                f"({top_count}/{len(deduped)} results). Filtering noise."
            )
            # Keep only results that differ from the catch-all
            filtered = [f for f in deduped if f.redirect_url != top_target]
            filtered_count = len(deduped) - len(filtered)
            deduped = filtered

    duration = (datetime.utcnow() - start).total_seconds()

    return PathEnumerationResult(
        target=target,
        total_checked=total,
        total_found=len(deduped),
        filtered_count=filtered_count,
        catch_all_pattern=catch_all_pattern,
        duration_seconds=duration,
        found=deduped,
    )
