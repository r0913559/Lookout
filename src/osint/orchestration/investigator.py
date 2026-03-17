"""Main investigation orchestrator."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Type

import aiohttp

from osint.cache.manager import CacheManager
from osint.clients.base import BaseAPIClient
from osint.clients.virustotal import VirusTotalClient
from osint.clients.urlscan import URLScanClient
from osint.clients.abuseipdb import AbuseIPDBClient
from osint.clients.shodan import ShodanClient
from osint.clients.alienvault import AlienVaultClient
from osint.clients.rdap import RDAPClient
from osint.clients.crtsh import CrtshClient
from osint.clients.threatfox import ThreatFoxClient
from osint.clients.urlhaus import URLhausClient
from osint.core.config import Settings, get_settings
from osint.core.constants import APISource, IndicatorType, RiskLevel
from osint.core.exceptions import DetectionError, OSINTError
from osint.detection.indicator_type import detect_indicator_type
from osint.models.results import APIResult


@dataclass
class InvestigationResult:
    """Result of an investigation."""

    indicator_value: str
    indicator_type: IndicatorType
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Results from each API
    results: dict[APISource, APIResult] = field(default_factory=dict)

    # Aggregated risk assessment
    risk_score: Optional[float] = None
    risk_level: RiskLevel = RiskLevel.UNKNOWN

    # Metadata
    sources_queried: list[APISource] = field(default_factory=list)
    sources_failed: list[APISource] = field(default_factory=list)
    cached_sources: list[APISource] = field(default_factory=list)
    duration_seconds: float = 0.0

    def add_result(self, result: APIResult) -> None:
        """Add an API result."""
        self.results[result.source] = result
        if result.cached:
            self.cached_sources.append(result.source)

    @property
    def successful_results(self) -> list[APIResult]:
        """Get all successful results."""
        return [r for r in self.results.values() if r.success]

    @property
    def has_detections(self) -> bool:
        """Check if any source flagged this indicator."""
        return self.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "indicator_value": self.indicator_value,
            "indicator_type": self.indicator_type.value,
            "timestamp": self.timestamp.isoformat(),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "sources_queried": [s.value for s in self.sources_queried],
            "sources_failed": [s.value for s in self.sources_failed],
            "cached_sources": [s.value for s in self.cached_sources],
            "duration_seconds": self.duration_seconds,
            "results": {
                source.value: result.model_dump(exclude={"raw_data"})
                for source, result in self.results.items()
            },
        }


# Mapping of API sources to client classes
CLIENT_CLASSES: dict[APISource, Type[BaseAPIClient]] = {
    # Premium clients (require API key)
    APISource.VIRUSTOTAL: VirusTotalClient,
    APISource.URLSCAN: URLScanClient,
    APISource.ABUSEIPDB: AbuseIPDBClient,
    APISource.SHODAN: ShodanClient,
    APISource.ALIENVAULT: AlienVaultClient,
    # Free clients (no API key required)
    APISource.RDAP: RDAPClient,
    APISource.CRTSH: CrtshClient,
    APISource.THREATFOX: ThreatFoxClient,
    APISource.URLHAUS: URLhausClient,
}


class Investigator:
    """
    Main orchestrator for threat intelligence investigations.

    Coordinates multiple API clients, caching, and result aggregation.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        use_cache: bool = True,
    ):
        """
        Initialize the investigator.

        Args:
            settings: Application settings
            use_cache: Whether to use caching
        """
        self.settings = settings or get_settings()
        self.use_cache = use_cache and self.settings.cache.enabled
        self.logger = logging.getLogger("osint.investigator")

        # Initialize components
        self.cache = CacheManager(self.settings) if self.use_cache else None
        self._session: Optional[aiohttp.ClientSession] = None
        self._clients: dict[APISource, BaseAPIClient] = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create shared HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60)
            )
        return self._session

    async def _get_client(self, source: APISource) -> Optional[BaseAPIClient]:
        """Get or create a client for an API source."""
        if source in self._clients:
            return self._clients[source]

        client_class = CLIENT_CLASSES.get(source)
        if client_class is None:
            self.logger.debug(f"No client implementation for {source}")
            return None

        session = await self._get_session()
        client = client_class(settings=self.settings, session=session)

        if not client.is_available():
            self.logger.debug(f"Client {source} not available (disabled or no API key)")
            return None

        self._clients[source] = client
        return client

    def _select_clients(
        self,
        indicator_type: IndicatorType,
    ) -> list[APISource]:
        """
        Select which API sources to query based on indicator type.

        Args:
            indicator_type: The type of indicator

        Returns:
            List of API sources to query
        """
        # Map indicator types to relevant sources
        type_to_sources: dict[IndicatorType, list[APISource]] = {
            IndicatorType.DOMAIN: [
                APISource.VIRUSTOTAL,
                APISource.URLSCAN,
                APISource.RDAP,
                APISource.CRTSH,
                APISource.THREATFOX,
            ],
            IndicatorType.IPV4: [
                APISource.VIRUSTOTAL,
                APISource.ABUSEIPDB,
                APISource.SHODAN,
                APISource.RDAP,
                APISource.THREATFOX,
            ],
            IndicatorType.IPV6: [
                APISource.VIRUSTOTAL,
                APISource.ABUSEIPDB,
                APISource.SHODAN,
                APISource.RDAP,
                APISource.THREATFOX,
            ],
            IndicatorType.MD5: [
                APISource.VIRUSTOTAL,
                APISource.THREATFOX,
            ],
            IndicatorType.SHA1: [
                APISource.VIRUSTOTAL,
                APISource.THREATFOX,
            ],
            IndicatorType.SHA256: [
                APISource.VIRUSTOTAL,
                APISource.THREATFOX,
                APISource.TRIAGE,
            ],
            IndicatorType.URL: [
                APISource.VIRUSTOTAL,
                APISource.URLSCAN,
                APISource.URLHAUS,
                APISource.THREATFOX,
            ],
            IndicatorType.EMAIL: [
                APISource.VIRUSTOTAL,
            ],
        }

        sources = type_to_sources.get(indicator_type, [APISource.VIRUSTOTAL])

        # Filter to only enabled sources
        return [s for s in sources if self.settings.is_api_enabled(s.value)]

    async def _query_source(
        self,
        source: APISource,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[APIResult]:
        """
        Query a single source with caching.

        Args:
            source: The API source
            value: The indicator value
            indicator_type: The indicator type

        Returns:
            API result or None
        """
        # Check cache first
        if self.cache:
            cached = self.cache.get(source, indicator_type, value)
            if cached:
                self.logger.debug(f"Cache hit for {source.value}")
                return cached

        # Check daily quota before making API call
        daily_quota = self.settings.get_daily_quota(source.value)
        if daily_quota > 0 and self.cache:
            used_today = self.cache.get_daily_usage(source)
            if used_today >= daily_quota:
                self.logger.warning(
                    f"Daily quota reached for {source.value}: "
                    f"{used_today}/{daily_quota}"
                )
                return None
            remaining = daily_quota - used_today
            if remaining <= 10:
                self.logger.warning(
                    f"Low quota for {source.value}: {remaining} remaining today"
                )

        # Query the API
        client = await self._get_client(source)
        if client is None:
            return None

        try:
            result = await client.lookup(value, indicator_type)

            # Record the API call for quota tracking
            if self.cache:
                self.cache.record_api_call(source)

            # Cache successful results
            if result and result.success and self.cache:
                self.cache.set(result)

            return result

        except Exception as e:
            self.logger.error(f"Error querying {source.value}: {e}")
            return None

    def _calculate_risk_score(
        self,
        results: dict[APISource, APIResult],
    ) -> tuple[float, RiskLevel]:
        """
        Calculate weighted risk score from all results.

        Args:
            results: Dictionary of API results

        Returns:
            Tuple of (risk_score, risk_level)
        """
        weights = self.settings.risk_weights
        total_weight = 0.0
        weighted_score = 0.0

        for source, result in results.items():
            if not result.success:
                continue

            weight = weights.get(source.value, 0.1)

            # Get individual score
            score = result.risk_score
            if score is None:
                continue

            weighted_score += score * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0, RiskLevel.UNKNOWN

        final_score = weighted_score / total_weight
        risk_level = RiskLevel.from_score(final_score)

        return round(final_score, 1), risk_level

    async def investigate(
        self,
        value: str,
        indicator_type: Optional[IndicatorType] = None,
    ) -> InvestigationResult:
        """
        Perform a full investigation of an indicator.

        Args:
            value: The indicator value
            indicator_type: Optional indicator type (auto-detected if not provided)

        Returns:
            InvestigationResult with all findings
        """
        start_time = datetime.utcnow()

        # Detect indicator type if not provided
        if indicator_type is None:
            try:
                indicator_type = detect_indicator_type(value)
            except DetectionError as e:
                raise OSINTError(f"Could not detect indicator type: {e}")

        self.logger.info(f"Investigating {indicator_type.value}: {value}")

        # Create result object
        result = InvestigationResult(
            indicator_value=value,
            indicator_type=indicator_type,
        )

        # Select sources to query
        sources = self._select_clients(indicator_type)
        result.sources_queried = sources

        if not sources:
            self.logger.warning("No sources available for investigation")
            return result

        # Query all sources in parallel
        tasks = [
            self._query_source(source, value, indicator_type)
            for source in sources
        ]

        api_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for source, api_result in zip(sources, api_results):
            if isinstance(api_result, Exception):
                self.logger.error(f"Exception from {source}: {api_result}")
                result.sources_failed.append(source)
            elif api_result is None:
                result.sources_failed.append(source)
            else:
                result.add_result(api_result)

        # Calculate overall risk
        result.risk_score, result.risk_level = self._calculate_risk_score(result.results)

        # Record duration
        result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()

        # Log investigation
        if self.cache:
            self.cache.log_investigation(
                indicator_type,
                value,
                sources,
                int(result.risk_score) if result.risk_score else None,
            )

        self.logger.info(
            f"Investigation complete: {len(result.successful_results)}/{len(sources)} "
            f"sources, risk: {result.risk_level.value} ({result.risk_score})"
        )

        return result

    async def close(self) -> None:
        """Clean up resources."""
        # Close all clients
        for client in self._clients.values():
            await client.close()
        self._clients.clear()

        # Close shared session
        if self._session and not self._session.closed:
            await self._session.close()

        # Close cache
        if self.cache:
            self.cache.close()

    async def __aenter__(self) -> "Investigator":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
