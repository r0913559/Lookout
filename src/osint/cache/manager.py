"""Cache manager for storing and retrieving API results."""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional, Type, TypeVar

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session, sessionmaker

from osint.cache.models import ApiQuotaUsage, Base, CachedResult, InvestigationLog
from osint.core.config import Settings, get_settings
from osint.core.constants import APISource, IndicatorType
from osint.core.exceptions import CacheError
from osint.models.results import (
    APIResult,
    VirusTotalResult,
    URLScanResult,
    AbuseIPDBResult,
    ShodanResult,
    RDAPResult,
    CrtshResult,
    ThreatFoxResult,
    URLhausResult,
)

T = TypeVar("T", bound=APIResult)

# Mapping of source to result class
RESULT_CLASSES: dict[APISource, Type[APIResult]] = {
    APISource.VIRUSTOTAL: VirusTotalResult,
    APISource.URLSCAN: URLScanResult,
    APISource.ABUSEIPDB: AbuseIPDBResult,
    APISource.SHODAN: ShodanResult,
    APISource.RDAP: RDAPResult,
    APISource.CRTSH: CrtshResult,
    APISource.THREATFOX: ThreatFoxResult,
    APISource.URLHAUS: URLhausResult,
}


class CacheManager:
    """
    Manages caching of API results using SQLite.

    Provides TTL-based caching with automatic expiration.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize the cache manager.

        Args:
            settings: Application settings (uses default if not provided)
        """
        self.settings = settings or get_settings()
        self.logger = logging.getLogger("osint.cache")
        self._engine: Any = None
        self._session_maker: Optional[sessionmaker] = None

    def _get_database_url(self) -> str:
        """Get the SQLite database URL."""
        cache_path = self.settings.get_cache_path()
        # Ensure directory exists
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{cache_path}"

    def _ensure_initialized(self) -> None:
        """Ensure the database is initialized."""
        if self._engine is None:
            database_url = self._get_database_url()
            self._engine = create_engine(database_url)
            Base.metadata.create_all(self._engine)
            self._session_maker = sessionmaker(bind=self._engine)
            self.logger.debug(f"Initialized cache database: {database_url}")

    def _get_session(self) -> Session:
        """Get a new database session."""
        self._ensure_initialized()
        if self._session_maker is None:
            raise CacheError("Session maker not initialized")
        return self._session_maker()

    def get(
        self,
        source: APISource,
        indicator_type: IndicatorType,
        indicator_value: str,
    ) -> Optional[APIResult]:
        """
        Retrieve a cached result.

        Args:
            source: The API source
            indicator_type: Type of indicator
            indicator_value: The indicator value

        Returns:
            The cached result or None if not found/expired
        """
        if not self.settings.cache.enabled:
            return None

        try:
            with self._get_session() as session:
                stmt = select(CachedResult).where(
                    CachedResult.source == source.value,
                    CachedResult.indicator_type == indicator_type.value,
                    CachedResult.indicator_value == indicator_value.lower(),
                )
                cached = session.execute(stmt).scalar_one_or_none()

                if cached is None:
                    return None

                if cached.is_expired():
                    # Clean up expired entry
                    session.delete(cached)
                    session.commit()
                    return None

                # Deserialize the result
                result_data = json.loads(cached.result_json)
                result_class = RESULT_CLASSES.get(source, APIResult)
                result = result_class(**result_data)
                result.cached = True

                self.logger.debug(
                    f"Cache hit: {source.value}/{indicator_type.value}/{indicator_value}"
                )
                return result

        except Exception as e:
            self.logger.warning(f"Cache get failed: {e}")
            return None

    def set(
        self,
        result: APIResult,
        ttl_hours: Optional[int] = None,
    ) -> bool:
        """
        Store a result in the cache.

        Args:
            result: The API result to cache
            ttl_hours: Optional TTL override in hours

        Returns:
            True if successfully cached
        """
        if not self.settings.cache.enabled:
            return False

        if not result.success:
            # Don't cache failed results
            return False

        try:
            # Determine TTL
            if ttl_hours is None:
                ttl_hours = self.settings.get_cache_ttl(result.source.value)

            expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)

            # Serialize result (exclude raw_data to save space, exclude cached flag)
            result_data = result.model_dump(exclude={"raw_data", "cached"})
            result_json = json.dumps(result_data, default=str)

            with self._get_session() as session:
                # Upsert: delete existing and insert new
                stmt = delete(CachedResult).where(
                    CachedResult.source == result.source.value,
                    CachedResult.indicator_type == result.indicator_type.value,
                    CachedResult.indicator_value == result.indicator_value.lower(),
                )
                session.execute(stmt)

                cached = CachedResult(
                    source=result.source.value,
                    indicator_type=result.indicator_type.value,
                    indicator_value=result.indicator_value.lower(),
                    result_json=result_json,
                    expires_at=expires_at,
                )
                session.add(cached)
                session.commit()

                self.logger.debug(
                    f"Cached: {result.source.value}/{result.indicator_type.value}"
                    f"/{result.indicator_value} (TTL: {ttl_hours}h)"
                )
                return True

        except Exception as e:
            self.logger.warning(f"Cache set failed: {e}")
            return False

    def delete(
        self,
        source: APISource,
        indicator_type: IndicatorType,
        indicator_value: str,
    ) -> bool:
        """
        Delete a specific cached result.

        Args:
            source: The API source
            indicator_type: Type of indicator
            indicator_value: The indicator value

        Returns:
            True if an entry was deleted
        """
        try:
            with self._get_session() as session:
                stmt = delete(CachedResult).where(
                    CachedResult.source == source.value,
                    CachedResult.indicator_type == indicator_type.value,
                    CachedResult.indicator_value == indicator_value.lower(),
                )
                result = session.execute(stmt)
                session.commit()
                return result.rowcount > 0

        except Exception as e:
            self.logger.warning(f"Cache delete failed: {e}")
            return False

    def clean_expired(self) -> int:
        """
        Remove all expired cache entries.

        Returns:
            Number of entries removed
        """
        try:
            with self._get_session() as session:
                stmt = delete(CachedResult).where(
                    CachedResult.expires_at < datetime.utcnow()
                )
                result = session.execute(stmt)
                session.commit()
                count = result.rowcount
                self.logger.info(f"Cleaned {count} expired cache entries")
                return count

        except Exception as e:
            self.logger.warning(f"Cache clean failed: {e}")
            return 0

    def clear_all(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries removed
        """
        try:
            with self._get_session() as session:
                stmt = delete(CachedResult)
                result = session.execute(stmt)
                session.commit()
                count = result.rowcount
                self.logger.info(f"Cleared {count} cache entries")
                return count

        except Exception as e:
            self.logger.warning(f"Cache clear failed: {e}")
            return 0

    def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        try:
            with self._get_session() as session:
                total = session.query(CachedResult).count()
                expired = (
                    session.query(CachedResult)
                    .filter(CachedResult.expires_at < datetime.utcnow())
                    .count()
                )

                # Count by source
                by_source = {}
                for source in APISource:
                    count = (
                        session.query(CachedResult)
                        .filter(CachedResult.source == source.value)
                        .count()
                    )
                    if count > 0:
                        by_source[source.value] = count

                return {
                    "total_entries": total,
                    "expired_entries": expired,
                    "active_entries": total - expired,
                    "by_source": by_source,
                    "database_path": str(self.settings.get_cache_path()),
                }

        except Exception as e:
            self.logger.warning(f"Failed to get cache stats: {e}")
            return {"error": str(e)}

    def log_investigation(
        self,
        indicator_type: IndicatorType,
        indicator_value: str,
        sources: list[APISource],
        risk_score: Optional[int] = None,
    ) -> None:
        """
        Log an investigation for analytics.

        Args:
            indicator_type: Type of indicator investigated
            indicator_value: The indicator value
            sources: List of sources queried
            risk_score: Overall risk score if calculated
        """
        try:
            with self._get_session() as session:
                log = InvestigationLog(
                    indicator_type=indicator_type.value,
                    indicator_value=indicator_value,
                    sources_queried=json.dumps([s.value for s in sources]),
                    risk_score=risk_score,
                )
                session.add(log)
                session.commit()

        except Exception as e:
            self.logger.warning(f"Failed to log investigation: {e}")

    def record_api_call(self, source: APISource) -> None:
        """Record an API call for daily quota tracking."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        try:
            with self._get_session() as session:
                existing = (
                    session.query(ApiQuotaUsage)
                    .filter(
                        ApiQuotaUsage.source == source.value,
                        ApiQuotaUsage.date == today,
                    )
                    .first()
                )
                if existing:
                    existing.request_count += 1
                else:
                    session.add(ApiQuotaUsage(
                        source=source.value,
                        date=today,
                        request_count=1,
                    ))
                session.commit()
        except Exception as e:
            self.logger.warning(f"Failed to record API call: {e}")

    def get_daily_usage(self, source: APISource) -> int:
        """Get today's API call count for a source."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        try:
            with self._get_session() as session:
                existing = (
                    session.query(ApiQuotaUsage)
                    .filter(
                        ApiQuotaUsage.source == source.value,
                        ApiQuotaUsage.date == today,
                    )
                    .first()
                )
                return existing.request_count if existing else 0
        except Exception:
            return 0

    def get_all_daily_usage(self) -> dict[str, int]:
        """Get today's API call counts for all sources."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        try:
            with self._get_session() as session:
                rows = (
                    session.query(ApiQuotaUsage)
                    .filter(ApiQuotaUsage.date == today)
                    .all()
                )
                return {row.source: row.request_count for row in rows}
        except Exception:
            return {}

    def close(self) -> None:
        """Close the database connection."""
        if self._engine:
            self._engine.dispose()
            self._engine = None
            self._session_maker = None
