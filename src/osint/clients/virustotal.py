"""VirusTotal API client."""

import base64
from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import VirusTotalResult


class VirusTotalClient(BaseAPIClient[VirusTotalResult]):
    """
    VirusTotal API v3 client.

    Supports lookups for domains, IPs, URLs, and file hashes.
    Free tier: 4 requests/minute, 500 requests/day.
    """

    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"
    requires_auth = True
    source = APISource.VIRUSTOTAL

    def _get_auth_headers(self) -> dict[str, str]:
        """Get VirusTotal authentication headers."""
        api_key = self.settings.get_api_key("virustotal")
        if api_key:
            return {"x-apikey": api_key}
        return {}

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """VirusTotal supports all indicator types."""
        return indicator_type in (
            IndicatorType.DOMAIN,
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.MD5,
            IndicatorType.SHA1,
            IndicatorType.SHA256,
            IndicatorType.URL,
        )

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[VirusTotalResult]:
        """
        Lookup an indicator in VirusTotal.

        Args:
            value: The indicator value
            indicator_type: The type of indicator

        Returns:
            VirusTotalResult or None
        """
        try:
            if indicator_type == IndicatorType.DOMAIN:
                return await self._lookup_domain(value)
            elif indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
                return await self._lookup_ip(value)
            elif indicator_type in (
                IndicatorType.MD5,
                IndicatorType.SHA1,
                IndicatorType.SHA256,
            ):
                return await self._lookup_hash(value, indicator_type)
            elif indicator_type == IndicatorType.URL:
                return await self._lookup_url(value)
            else:
                self.logger.warning(f"Unsupported indicator type: {indicator_type}")
                return None

        except Exception as e:
            self.logger.error(f"Lookup failed for {value}: {e}")
            return VirusTotalResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _lookup_domain(self, domain: str) -> VirusTotalResult:
        """Lookup a domain."""
        data = await self._request("GET", f"/domains/{domain}")
        return self._parse_domain_response(domain, data)

    async def _lookup_ip(self, ip: str) -> VirusTotalResult:
        """Lookup an IP address."""
        data = await self._request("GET", f"/ip_addresses/{ip}")
        indicator_type = IndicatorType.IPV6 if ":" in ip else IndicatorType.IPV4
        return self._parse_ip_response(ip, indicator_type, data)

    async def _lookup_hash(
        self,
        hash_value: str,
        hash_type: IndicatorType,
    ) -> VirusTotalResult:
        """Lookup a file hash."""
        data = await self._request("GET", f"/files/{hash_value}")
        return self._parse_file_response(hash_value, hash_type, data)

    async def _lookup_url(self, url: str) -> VirusTotalResult:
        """Lookup a URL."""
        # VT requires URL to be base64 encoded (without padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = await self._request("GET", f"/urls/{url_id}")
        return self._parse_url_response(url, data)

    def _parse_domain_response(
        self,
        domain: str,
        data: dict[str, Any],
    ) -> VirusTotalResult:
        """Parse domain lookup response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = VirusTotalResult(
            indicator_type=IndicatorType.DOMAIN,
            indicator_value=domain,
            raw_data=data,
            # Detection stats
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_scanners=sum(stats.values()) if stats else 0,
            # Metadata
            reputation=attrs.get("reputation"),
            categories=attrs.get("categories", {}),
            tags=attrs.get("tags", []),
            # Domain-specific
            registrar=attrs.get("registrar"),
            whois=attrs.get("whois"),
        )

        # Parse dates
        if "creation_date" in attrs:
            result.creation_date = datetime.fromtimestamp(attrs["creation_date"])
        if "last_analysis_date" in attrs:
            result.last_analysis_date = datetime.fromtimestamp(
                attrs["last_analysis_date"]
            )

        result.calculate_risk_score()
        return result

    def _parse_ip_response(
        self,
        ip: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> VirusTotalResult:
        """Parse IP lookup response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = VirusTotalResult(
            indicator_type=indicator_type,
            indicator_value=ip,
            raw_data=data,
            # Detection stats
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_scanners=sum(stats.values()) if stats else 0,
            # Metadata
            reputation=attrs.get("reputation"),
            tags=attrs.get("tags", []),
            # IP-specific
            asn=attrs.get("asn"),
            as_owner=attrs.get("as_owner"),
            country=attrs.get("country"),
        )

        if "last_analysis_date" in attrs:
            result.last_analysis_date = datetime.fromtimestamp(
                attrs["last_analysis_date"]
            )

        result.calculate_risk_score()
        return result

    def _parse_file_response(
        self,
        hash_value: str,
        hash_type: IndicatorType,
        data: dict[str, Any],
    ) -> VirusTotalResult:
        """Parse file hash lookup response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = VirusTotalResult(
            indicator_type=hash_type,
            indicator_value=hash_value,
            raw_data=data,
            # Detection stats
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_scanners=sum(stats.values()) if stats else 0,
            # Metadata
            reputation=attrs.get("reputation"),
            tags=attrs.get("tags", []),
            # File-specific
            file_name=attrs.get("meaningful_name") or attrs.get("names", [None])[0],
            file_type=attrs.get("type_description"),
            file_size=attrs.get("size"),
            magic=attrs.get("magic"),
            sha256=attrs.get("sha256"),
            sha1=attrs.get("sha1"),
            md5=attrs.get("md5"),
        )

        if "last_analysis_date" in attrs:
            result.last_analysis_date = datetime.fromtimestamp(
                attrs["last_analysis_date"]
            )

        result.calculate_risk_score()
        return result

    def _parse_url_response(
        self,
        url: str,
        data: dict[str, Any],
    ) -> VirusTotalResult:
        """Parse URL lookup response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = VirusTotalResult(
            indicator_type=IndicatorType.URL,
            indicator_value=url,
            raw_data=data,
            # Detection stats
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_scanners=sum(stats.values()) if stats else 0,
            # Metadata
            reputation=attrs.get("reputation"),
            categories=attrs.get("categories", {}),
            tags=attrs.get("tags", []),
        )

        if "last_analysis_date" in attrs:
            result.last_analysis_date = datetime.fromtimestamp(
                attrs["last_analysis_date"]
            )

        result.calculate_risk_score()
        return result

    async def get_domain_communicating_files(
        self,
        domain: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get files that communicate with a domain."""
        data = await self._request(
            "GET",
            f"/domains/{domain}/communicating_files",
            params={"limit": limit},
        )
        return data.get("data", [])

    async def get_ip_communicating_files(
        self,
        ip: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get files that communicate with an IP."""
        data = await self._request(
            "GET",
            f"/ip_addresses/{ip}/communicating_files",
            params={"limit": limit},
        )
        return data.get("data", [])

    async def get_domain_resolutions(
        self,
        domain: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get DNS resolutions for a domain."""
        data = await self._request(
            "GET",
            f"/domains/{domain}/resolutions",
            params={"limit": limit},
        )
        return data.get("data", [])

    async def get_file_behavior(self, file_hash: str) -> dict[str, Any]:
        """Get behavioral analysis for a file."""
        data = await self._request("GET", f"/files/{file_hash}/behaviour_summary")
        return data
