"""AbuseIPDB API client."""

from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import AbuseIPDBResult


class AbuseIPDBClient(BaseAPIClient[AbuseIPDBResult]):
    """
    AbuseIPDB API client.

    Provides IP reputation and abuse reports.
    """

    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"
    requires_auth = True
    source = APISource.ABUSEIPDB

    def _get_auth_headers(self) -> dict[str, str]:
        """Get AbuseIPDB authentication headers."""
        api_key = self.settings.get_api_key("abuseipdb")
        if api_key:
            return {"Key": api_key}
        return {}

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """AbuseIPDB only supports IP addresses."""
        return indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6)

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[AbuseIPDBResult]:
        """Check an IP address against AbuseIPDB."""
        if indicator_type not in (IndicatorType.IPV4, IndicatorType.IPV6):
            return None

        try:
            return await self._check_ip(value, indicator_type)
        except Exception as e:
            self.logger.error(f"AbuseIPDB lookup failed for {value}: {e}")
            return AbuseIPDBResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _check_ip(
        self,
        ip: str,
        indicator_type: IndicatorType,
    ) -> AbuseIPDBResult:
        """Check IP reputation."""
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "true",
        }

        data = await self._request("GET", "/check", params=params)
        return self._parse_response(ip, indicator_type, data)

    def _parse_response(
        self,
        ip: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> AbuseIPDBResult:
        """Parse AbuseIPDB response."""
        ip_data = data.get("data", {})

        result = AbuseIPDBResult(
            indicator_type=indicator_type,
            indicator_value=ip,
            raw_data=data,
            ip_address=ip_data.get("ipAddress"),
            is_public=ip_data.get("isPublic", True),
            ip_version=ip_data.get("ipVersion", 4),
            is_whitelisted=ip_data.get("isWhitelisted", False),
            abuse_confidence_score=ip_data.get("abuseConfidenceScore", 0),
            total_reports=ip_data.get("totalReports", 0),
            num_distinct_users=ip_data.get("numDistinctUsers", 0),
            isp=ip_data.get("isp"),
            domain=ip_data.get("domain"),
            country_code=ip_data.get("countryCode"),
            country_name=ip_data.get("countryName"),
            usage_type=ip_data.get("usageType"),
        )

        # Parse last reported date
        last_reported = ip_data.get("lastReportedAt")
        if last_reported:
            try:
                result.last_reported_at = datetime.fromisoformat(
                    last_reported.replace("Z", "+00:00")
                )
            except Exception:
                pass

        # Parse reports if available
        reports = ip_data.get("reports", [])
        result.reports = reports[:20]  # Limit stored reports

        # Calculate risk score
        result.calculate_risk_score()

        return result

    async def report_ip(
        self,
        ip: str,
        categories: list[int],
        comment: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Report an IP address for abuse.

        Args:
            ip: IP address to report
            categories: List of category IDs (see AbuseIPDB docs)
            comment: Optional comment about the abuse

        Returns:
            API response
        """
        payload = {
            "ip": ip,
            "categories": ",".join(map(str, categories)),
        }
        if comment:
            payload["comment"] = comment

        return await self._request("POST", "/report", json_data=payload)

    async def check_block(self, network: str) -> dict[str, Any]:
        """
        Check an entire CIDR block.

        Args:
            network: CIDR notation (e.g., "192.168.1.0/24")

        Returns:
            API response with reported addresses in the block
        """
        params = {"network": network}
        return await self._request("GET", "/check-block", params=params)

    async def get_blacklist(
        self,
        confidence_minimum: int = 90,
        limit: int = 10000,
    ) -> list[dict[str, Any]]:
        """
        Get the AbuseIPDB blacklist.

        Args:
            confidence_minimum: Minimum confidence score (0-100)
            limit: Maximum number of IPs to return

        Returns:
            List of blacklisted IPs
        """
        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": limit,
        }
        data = await self._request("GET", "/blacklist", params=params)
        return data.get("data", [])
