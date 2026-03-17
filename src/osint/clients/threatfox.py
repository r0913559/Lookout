"""ThreatFox (abuse.ch) API client."""

from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import ThreatFoxResult


class ThreatFoxClient(BaseAPIClient[ThreatFoxResult]):
    """
    ThreatFox (abuse.ch) API client.

    No authentication required. Provides IOC data.
    """

    name = "threatfox"
    base_url = "https://threatfox-api.abuse.ch/api/v1"
    requires_auth = False
    source = APISource.THREATFOX

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """ThreatFox supports domains, IPs, URLs, and hashes."""
        return indicator_type in (
            IndicatorType.DOMAIN,
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.MD5,
            IndicatorType.SHA256,
            IndicatorType.URL,
        )

    def _get_ioc_type(self, indicator_type: IndicatorType) -> str:
        """Map indicator type to ThreatFox IOC type."""
        mapping = {
            IndicatorType.DOMAIN: "domain",
            IndicatorType.IPV4: "ip:port",
            IndicatorType.IPV6: "ip:port",
            IndicatorType.MD5: "md5_hash",
            IndicatorType.SHA256: "sha256_hash",
            IndicatorType.URL: "url",
        }
        return mapping.get(indicator_type, "domain")

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[ThreatFoxResult]:
        """Search ThreatFox for an IOC."""
        try:
            return await self._search_ioc(value, indicator_type)
        except Exception as e:
            self.logger.error(f"ThreatFox lookup failed for {value}: {e}")
            return ThreatFoxResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _search_ioc(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> ThreatFoxResult:
        """Search for an IOC in ThreatFox."""
        payload = {
            "query": "search_ioc",
            "search_term": value,
        }

        data = await self._request("POST", "/", json_data=payload)
        return self._parse_response(value, indicator_type, data)

    def _parse_response(
        self,
        value: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> ThreatFoxResult:
        """Parse ThreatFox response."""
        result = ThreatFoxResult(
            indicator_type=indicator_type,
            indicator_value=value,
            raw_data=data,
        )

        query_status = data.get("query_status")

        if query_status == "no_result":
            result.total_matches = 0
            result.risk_score = 0.0
            return result

        if query_status != "ok":
            result.success = False
            result.error_message = f"Query status: {query_status}"
            return result

        # Parse IOC matches
        iocs = data.get("data", [])
        result.ioc_matches = iocs
        result.total_matches = len(iocs)

        # Extract threat information
        threat_types = set()
        malware_families = set()
        confidence_levels = []
        first_seen = None
        last_seen = None

        for ioc in iocs:
            # Threat type
            threat_type = ioc.get("threat_type")
            if threat_type:
                threat_types.add(threat_type)

            # Malware family
            malware = ioc.get("malware")
            if malware:
                malware_families.add(malware)

            # Confidence
            confidence = ioc.get("confidence_level")
            if confidence is not None:
                confidence_levels.append(confidence)

            # Dates
            fs = self._parse_date(ioc.get("first_seen"))
            ls = self._parse_date(ioc.get("last_seen"))

            if fs:
                if first_seen is None or fs < first_seen:
                    first_seen = fs
            if ls:
                if last_seen is None or ls > last_seen:
                    last_seen = ls

        result.threat_types = list(threat_types)
        result.malware_families = list(malware_families)
        result.confidence_levels = confidence_levels
        result.first_seen = first_seen
        result.last_seen = last_seen

        # Calculate risk score
        result.calculate_risk_score()

        return result

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ThreatFox date format."""
        if not date_str:
            return None

        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            try:
                return datetime.strptime(date_str[:10], "%Y-%m-%d")
            except Exception:
                return None

    async def get_malware_info(self, malware_name: str) -> dict[str, Any]:
        """Get information about a malware family."""
        payload = {
            "query": "malwareinfo",
            "malware": malware_name,
        }
        return await self._request("POST", "/", json_data=payload)

    async def get_recent_iocs(self, days: int = 1) -> list[dict[str, Any]]:
        """Get recent IOCs from ThreatFox."""
        payload = {
            "query": "get_iocs",
            "days": days,
        }
        data = await self._request("POST", "/", json_data=payload)
        return data.get("data", [])
