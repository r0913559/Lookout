"""AlienVault OTX API client."""

from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import AlienVaultResult


class AlienVaultClient(BaseAPIClient[AlienVaultResult]):
    """
    AlienVault OTX (Open Threat Exchange) API client.

    Provides threat intelligence from community-sourced pulses.
    """

    name = "alienvault"
    base_url = "https://otx.alienvault.com/api/v1"
    requires_auth = True
    source = APISource.ALIENVAULT

    def _get_auth_headers(self) -> dict[str, str]:
        """Get AlienVault authentication headers."""
        api_key = self.settings.get_api_key("alienvault")
        if api_key:
            return {"X-OTX-API-KEY": api_key}
        return {}

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """AlienVault supports all common indicator types."""
        return indicator_type in (
            IndicatorType.DOMAIN,
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.MD5,
            IndicatorType.SHA1,
            IndicatorType.SHA256,
            IndicatorType.URL,
            IndicatorType.EMAIL,
        )

    def _get_otx_type(self, indicator_type: IndicatorType) -> str:
        """Map indicator type to OTX indicator type."""
        mapping = {
            IndicatorType.DOMAIN: "domain",
            IndicatorType.IPV4: "IPv4",
            IndicatorType.IPV6: "IPv6",
            IndicatorType.MD5: "file",
            IndicatorType.SHA1: "file",
            IndicatorType.SHA256: "file",
            IndicatorType.URL: "url",
            IndicatorType.EMAIL: "email",
        }
        return mapping.get(indicator_type, "domain")

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[AlienVaultResult]:
        """Lookup an indicator in AlienVault OTX."""
        try:
            otx_type = self._get_otx_type(indicator_type)

            if indicator_type in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256):
                return await self._lookup_file(value, indicator_type)
            else:
                return await self._lookup_general(value, indicator_type, otx_type)

        except Exception as e:
            self.logger.error(f"AlienVault lookup failed for {value}: {e}")
            return AlienVaultResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _lookup_general(
        self,
        value: str,
        indicator_type: IndicatorType,
        otx_type: str,
    ) -> AlienVaultResult:
        """Lookup domain, IP, URL, or email."""
        # Get general info
        data = await self._request("GET", f"/indicators/{otx_type}/{value}/general")
        return self._parse_general_response(value, indicator_type, data)

    async def _lookup_file(
        self,
        hash_value: str,
        indicator_type: IndicatorType,
    ) -> AlienVaultResult:
        """Lookup file hash."""
        data = await self._request("GET", f"/indicators/file/{hash_value}/general")
        return self._parse_file_response(hash_value, indicator_type, data)

    def _parse_general_response(
        self,
        value: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> AlienVaultResult:
        """Parse general indicator response."""
        result = AlienVaultResult(
            indicator_type=indicator_type,
            indicator_value=value,
            raw_data=data,
            pulse_count=data.get("pulse_info", {}).get("count", 0),
            reputation=data.get("reputation"),
            country_code=data.get("country_code"),
            asn=data.get("asn"),
        )

        # Parse pulses
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])

        result.pulses = [
            {
                "id": p.get("id"),
                "name": p.get("name"),
                "description": p.get("description", "")[:200],
                "author_name": p.get("author", {}).get("username"),
                "created": p.get("created"),
                "tags": p.get("tags", []),
            }
            for p in pulses[:10]
        ]

        # Extract related indicators from pulses
        related_domains = set()
        related_ips = set()
        related_hashes = set()
        related_urls = set()

        for pulse in pulses:
            for indicator in pulse.get("indicators", [])[:50]:
                ioc_type = indicator.get("type", "")
                ioc_value = indicator.get("indicator", "")

                if ioc_type == "domain":
                    related_domains.add(ioc_value)
                elif ioc_type in ("IPv4", "IPv6"):
                    related_ips.add(ioc_value)
                elif ioc_type in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"):
                    related_hashes.add(ioc_value)
                elif ioc_type == "URL":
                    related_urls.add(ioc_value)

        result.related_domains = list(related_domains)[:20]
        result.related_ips = list(related_ips)[:20]
        result.related_hashes = list(related_hashes)[:20]
        result.related_urls = list(related_urls)[:20]

        # Calculate risk score based on pulse count
        if result.pulse_count > 0:
            # More pulses = higher risk
            result.risk_score = min(30 + (result.pulse_count * 10), 100)
        else:
            result.risk_score = 0.0

        result.calculate_risk_level()

        return result

    def _parse_file_response(
        self,
        hash_value: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> AlienVaultResult:
        """Parse file hash response."""
        result = AlienVaultResult(
            indicator_type=indicator_type,
            indicator_value=hash_value,
            raw_data=data,
            pulse_count=data.get("pulse_info", {}).get("count", 0),
        )

        # Parse analysis results if available
        analysis = data.get("analysis", {})
        if analysis:
            plugins = analysis.get("plugins", {})
            if plugins:
                # Get AV detection info
                av_results = plugins.get("avresults", {}).get("results", {})
                if av_results:
                    result.risk_score = 80.0  # AV detections = high risk

        # Fall back to pulse-based scoring
        if result.risk_score is None:
            if result.pulse_count > 0:
                result.risk_score = min(40 + (result.pulse_count * 15), 100)
            else:
                result.risk_score = 0.0

        result.calculate_risk_level()

        return result

    async def get_pulses_subscribed(
        self,
        page: int = 1,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get pulses the user is subscribed to."""
        params = {"page": page, "limit": limit}
        data = await self._request("GET", "/pulses/subscribed", params=params)
        return data.get("results", [])

    async def get_pulse_details(self, pulse_id: str) -> dict[str, Any]:
        """Get details of a specific pulse."""
        return await self._request("GET", f"/pulses/{pulse_id}")

    async def get_pulse_indicators(
        self,
        pulse_id: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get indicators from a pulse."""
        params = {"limit": limit}
        data = await self._request(
            "GET",
            f"/pulses/{pulse_id}/indicators",
            params=params,
        )
        return data.get("results", [])
