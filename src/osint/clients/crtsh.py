"""crt.sh Certificate Transparency client."""

from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import CrtshResult


class CrtshClient(BaseAPIClient[CrtshResult]):
    """
    crt.sh Certificate Transparency log client.

    No authentication required. Useful for subdomain enumeration.
    """

    name = "crtsh"
    base_url = "https://crt.sh"
    requires_auth = False
    source = APISource.CRTSH

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """crt.sh only supports domains."""
        return indicator_type == IndicatorType.DOMAIN

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[CrtshResult]:
        """Lookup certificates for a domain."""
        if indicator_type != IndicatorType.DOMAIN:
            return None

        try:
            return await self._lookup_domain(value)
        except Exception as e:
            self.logger.error(f"crt.sh lookup failed for {value}: {e}")
            return CrtshResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _lookup_domain(self, domain: str) -> CrtshResult:
        """Lookup certificates for a domain."""
        # Query with wildcard to get subdomains
        params = {
            "q": f"%.{domain}",
            "output": "json",
        }

        data = await self._request("GET", "/", params=params)

        return self._parse_response(domain, data)

    def _parse_response(
        self,
        domain: str,
        data: Any,
    ) -> CrtshResult:
        """Parse crt.sh response."""
        result = CrtshResult(
            indicator_type=IndicatorType.DOMAIN,
            indicator_value=domain,
        )

        if not isinstance(data, list):
            result.raw_data = {"response": data}
            return result

        result.raw_data = {"certificates": data[:100]}  # Limit stored data

        # Extract unique subdomains
        subdomains = set()
        certificates = []

        for entry in data:
            # Extract certificate info
            cert_info = {
                "id": entry.get("id"),
                "issuer_name": entry.get("issuer_name"),
                "name_value": entry.get("name_value"),
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
            }
            certificates.append(cert_info)

            # Extract domains from name_value (can have multiple)
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    # Validate it's related to our domain
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)

        # Sort and deduplicate
        result.subdomains = sorted(subdomains)
        result.certificates = certificates[:50]  # Limit to 50 most recent
        result.total_certificates = len(data)

        return result

    async def get_certificate_details(self, cert_id: int) -> dict[str, Any]:
        """Get detailed information about a specific certificate."""
        params = {"d": str(cert_id)}
        return await self._request("GET", "/", params=params)
