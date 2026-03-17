"""URLhaus (abuse.ch) API client."""

from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import URLhausResult


class URLhausClient(BaseAPIClient[URLhausResult]):
    """
    URLhaus (abuse.ch) API client.

    No authentication required. Provides malicious URL data.
    """

    name = "urlhaus"
    base_url = "https://urlhaus-api.abuse.ch/v1"
    requires_auth = False
    source = APISource.URLHAUS

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """URLhaus supports URLs, domains, and IPs."""
        return indicator_type in (
            IndicatorType.URL,
            IndicatorType.DOMAIN,
            IndicatorType.IPV4,
            IndicatorType.MD5,
            IndicatorType.SHA256,
        )

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[URLhausResult]:
        """Lookup an indicator in URLhaus."""
        try:
            if indicator_type == IndicatorType.URL:
                return await self._lookup_url(value)
            elif indicator_type == IndicatorType.DOMAIN:
                return await self._lookup_host(value, indicator_type)
            elif indicator_type == IndicatorType.IPV4:
                return await self._lookup_host(value, indicator_type)
            elif indicator_type in (IndicatorType.MD5, IndicatorType.SHA256):
                return await self._lookup_payload(value, indicator_type)
            else:
                return None
        except Exception as e:
            self.logger.error(f"URLhaus lookup failed for {value}: {e}")
            return URLhausResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _lookup_url(self, url: str) -> URLhausResult:
        """Lookup a specific URL."""
        payload = {"url": url}
        data = await self._request("POST", "/url/", json_data=payload)
        return self._parse_url_response(url, data)

    async def _lookup_host(
        self,
        host: str,
        indicator_type: IndicatorType,
    ) -> URLhausResult:
        """Lookup URLs associated with a host (domain or IP)."""
        payload = {"host": host}
        data = await self._request("POST", "/host/", json_data=payload)
        return self._parse_host_response(host, indicator_type, data)

    async def _lookup_payload(
        self,
        hash_value: str,
        indicator_type: IndicatorType,
    ) -> URLhausResult:
        """Lookup a payload hash."""
        hash_type = "md5_hash" if indicator_type == IndicatorType.MD5 else "sha256_hash"
        payload = {hash_type: hash_value}
        data = await self._request("POST", "/payload/", json_data=payload)
        return self._parse_payload_response(hash_value, indicator_type, data)

    def _parse_url_response(
        self,
        url: str,
        data: dict[str, Any],
    ) -> URLhausResult:
        """Parse URL lookup response."""
        result = URLhausResult(
            indicator_type=IndicatorType.URL,
            indicator_value=url,
            raw_data=data,
        )

        query_status = data.get("query_status")

        if query_status == "no_results":
            result.risk_score = 0.0
            return result

        if query_status != "ok":
            result.success = False
            result.error_message = f"Query status: {query_status}"
            return result

        # Parse URL data
        result.url_id = data.get("id")
        result.url_status = data.get("url_status")
        result.threat = data.get("threat")
        result.host = data.get("host")
        result.tags = data.get("tags", [])

        # Parse dates
        result.date_added = self._parse_date(data.get("date_added"))
        result.last_online = self._parse_date(data.get("last_online"))

        # Parse payloads
        result.payloads = data.get("payloads", [])

        # Parse blacklist status
        result.blacklists = data.get("blacklists", {})

        # Calculate risk score
        result.calculate_risk_score()

        return result

    def _parse_host_response(
        self,
        host: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> URLhausResult:
        """Parse host lookup response."""
        result = URLhausResult(
            indicator_type=indicator_type,
            indicator_value=host,
            raw_data=data,
            host=host,
        )

        query_status = data.get("query_status")

        if query_status == "no_results":
            result.risk_score = 0.0
            return result

        if query_status != "ok":
            result.success = False
            result.error_message = f"Query status: {query_status}"
            return result

        # Get URL count
        url_count = data.get("url_count", 0)

        # Parse URLs (limited)
        urls = data.get("urls", [])

        # Aggregate tags from all URLs
        all_tags = set()
        threats = set()
        for url_info in urls[:50]:
            tags = url_info.get("tags", [])
            if tags:
                all_tags.update(tags)
            threat = url_info.get("threat")
            if threat:
                threats.add(threat)

        result.tags = list(all_tags)

        # Use most common threat type
        if threats:
            result.threat = list(threats)[0]

        # Calculate risk based on URL count
        if url_count > 0:
            # More URLs = higher risk
            result.risk_score = min(50 + (url_count * 5), 100)
        else:
            result.risk_score = 0.0

        result.calculate_risk_level()

        return result

    def _parse_payload_response(
        self,
        hash_value: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> URLhausResult:
        """Parse payload lookup response."""
        result = URLhausResult(
            indicator_type=indicator_type,
            indicator_value=hash_value,
            raw_data=data,
        )

        query_status = data.get("query_status")

        if query_status == "no_results":
            result.risk_score = 0.0
            return result

        if query_status != "ok":
            result.success = False
            result.error_message = f"Query status: {query_status}"
            return result

        # Parse payload info
        result.tags = data.get("signature", "").split(",") if data.get("signature") else []

        # Get associated URLs
        urls = data.get("urls", [])
        result.payloads = [
            {
                "url": u.get("url"),
                "url_status": u.get("url_status"),
                "filename": u.get("filename"),
            }
            for u in urls[:20]
        ]

        # Payload found = definitely malicious
        result.risk_score = 85.0
        result.threat = "malware_download"
        result.calculate_risk_level()

        return result

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse URLhaus date format."""
        if not date_str:
            return None

        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            try:
                return datetime.strptime(date_str, "%Y-%m-%d")
            except Exception:
                return None

    async def get_recent_urls(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recently added malicious URLs."""
        data = await self._request("GET", "/urls/recent/limit/{limit}/")
        return data.get("urls", [])
