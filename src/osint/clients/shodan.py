"""Shodan API client."""

from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import ShodanResult


class ShodanClient(BaseAPIClient[ShodanResult]):
    """
    Shodan API client.

    Provides port scanning and service information.
    """

    name = "shodan"
    base_url = "https://api.shodan.io"
    requires_auth = True
    source = APISource.SHODAN

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """Shodan supports IPs and domains."""
        return indicator_type in (
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.DOMAIN,
        )

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Override to add API key as query parameter."""
        if params is None:
            params = {}

        api_key = self.settings.get_api_key("shodan")
        if api_key:
            params["key"] = api_key

        return await super()._request(method, endpoint, params=params, **kwargs)

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[ShodanResult]:
        """Lookup host information in Shodan."""
        try:
            if indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
                return await self._lookup_ip(value, indicator_type)
            elif indicator_type == IndicatorType.DOMAIN:
                return await self._lookup_domain(value)
            else:
                return None
        except Exception as e:
            self.logger.error(f"Shodan lookup failed for {value}: {e}")
            return ShodanResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _lookup_ip(
        self,
        ip: str,
        indicator_type: IndicatorType,
    ) -> ShodanResult:
        """Lookup IP host information."""
        data = await self._request("GET", f"/shodan/host/{ip}")
        return self._parse_host_response(ip, indicator_type, data)

    async def _lookup_domain(self, domain: str) -> ShodanResult:
        """Lookup domain DNS information."""
        data = await self._request("GET", f"/dns/domain/{domain}")
        return self._parse_domain_response(domain, data)

    def _parse_host_response(
        self,
        ip: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> ShodanResult:
        """Parse Shodan host response."""
        result = ShodanResult(
            indicator_type=indicator_type,
            indicator_value=ip,
            raw_data=data,
            ip_str=data.get("ip_str"),
            hostnames=data.get("hostnames", []),
            domains=data.get("domains", []),
            country_code=data.get("country_code"),
            country_name=data.get("country_name"),
            city=data.get("city"),
            org=data.get("org"),
            isp=data.get("isp"),
            asn=data.get("asn"),
            os=data.get("os"),
            ports=data.get("ports", []),
            vulns=data.get("vulns", []),
            tags=data.get("tags", []),
        )

        # Parse services
        services = []
        for service in data.get("data", []):
            service_info = {
                "port": service.get("port"),
                "transport": service.get("transport"),
                "product": service.get("product"),
                "version": service.get("version"),
                "banner": service.get("data", "")[:200],  # Truncate banner
            }
            services.append(service_info)
        result.services = services

        # Parse last update
        last_update = data.get("last_update")
        if last_update:
            try:
                result.last_update = datetime.fromisoformat(last_update.replace("Z", "+00:00"))
            except Exception:
                pass

        # Calculate risk score based on vulnerabilities and exposed services
        risk_score = 0.0

        # Vulnerabilities are high risk
        if result.vulns:
            risk_score += min(len(result.vulns) * 15, 60)

        # Many open ports increase risk
        if len(result.ports) > 10:
            risk_score += 20
        elif len(result.ports) > 5:
            risk_score += 10

        # Certain ports are higher risk
        high_risk_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432}
        exposed_risky = set(result.ports) & high_risk_ports
        risk_score += len(exposed_risky) * 5

        result.risk_score = min(risk_score, 100)
        result.calculate_risk_level()

        return result

    def _parse_domain_response(
        self,
        domain: str,
        data: dict[str, Any],
    ) -> ShodanResult:
        """Parse Shodan domain DNS response."""
        result = ShodanResult(
            indicator_type=IndicatorType.DOMAIN,
            indicator_value=domain,
            raw_data=data,
            domains=[domain],
        )

        # Extract hostnames from DNS data
        subdomains = set()
        for record_type in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
            records = data.get(record_type, [])
            for record in records:
                subdomain = record.get("subdomain")
                if subdomain:
                    full_domain = f"{subdomain}.{domain}" if subdomain != "@" else domain
                    subdomains.add(full_domain)

        result.hostnames = list(subdomains)

        return result

    async def search(
        self,
        query: str,
        page: int = 1,
    ) -> dict[str, Any]:
        """
        Search Shodan.

        Args:
            query: Shodan search query
            page: Results page number

        Returns:
            Search results
        """
        params = {
            "query": query,
            "page": page,
        }
        return await self._request("GET", "/shodan/host/search", params=params)

    async def get_ports(self) -> list[int]:
        """Get list of ports Shodan crawls."""
        data = await self._request("GET", "/shodan/ports")
        return data if isinstance(data, list) else []

    async def resolve_dns(self, hostnames: list[str]) -> dict[str, str]:
        """
        Resolve hostnames to IPs.

        Args:
            hostnames: List of hostnames to resolve

        Returns:
            Dictionary mapping hostname to IP
        """
        params = {"hostnames": ",".join(hostnames)}
        return await self._request("GET", "/dns/resolve", params=params)

    async def reverse_dns(self, ips: list[str]) -> dict[str, list[str]]:
        """
        Reverse DNS lookup.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary mapping IP to hostnames
        """
        params = {"ips": ",".join(ips)}
        return await self._request("GET", "/dns/reverse", params=params)
