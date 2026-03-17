"""RDAP (Registration Data Access Protocol) client for WHOIS lookups."""

import ipaddress
from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import RDAPResult


class RDAPClient(BaseAPIClient[RDAPResult]):
    """
    RDAP client for WHOIS/registration data lookups.

    No authentication required. Uses public RDAP servers.
    """

    name = "rdap"
    base_url = "https://rdap.org"  # Meta RDAP redirector
    requires_auth = False
    source = APISource.RDAP

    # Alternative RDAP endpoints
    DOMAIN_RDAP_URL = "https://rdap.org/domain"
    IP_RDAP_URL = "https://rdap.org/ip"

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """RDAP supports domains and IPs."""
        return indicator_type in (
            IndicatorType.DOMAIN,
            IndicatorType.IPV4,
            IndicatorType.IPV6,
        )

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[RDAPResult]:
        """Lookup registration data for a domain or IP."""
        try:
            if indicator_type == IndicatorType.DOMAIN:
                return await self._lookup_domain(value)
            elif indicator_type in (IndicatorType.IPV4, IndicatorType.IPV6):
                return await self._lookup_ip(value, indicator_type)
            else:
                return None
        except Exception as e:
            self.logger.error(f"RDAP lookup failed for {value}: {e}")
            return RDAPResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _lookup_domain(self, domain: str) -> RDAPResult:
        """Lookup domain registration data."""
        data = await self._request("GET", f"/domain/{domain}")
        return self._parse_domain_response(domain, data)

    async def _lookup_ip(
        self,
        ip: str,
        indicator_type: IndicatorType,
    ) -> RDAPResult:
        """Lookup IP registration data."""
        data = await self._request("GET", f"/ip/{ip}")
        return self._parse_ip_response(ip, indicator_type, data)

    def _parse_domain_response(
        self,
        domain: str,
        data: dict[str, Any],
    ) -> RDAPResult:
        """Parse RDAP domain response."""
        result = RDAPResult(
            indicator_type=IndicatorType.DOMAIN,
            indicator_value=domain,
            raw_data=data,
            domain_name=data.get("ldhName") or data.get("unicodeName"),
        )

        # Extract entities (registrar, registrant, etc.)
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = self._parse_vcard(entity.get("vcardArray", []))

            if "registrar" in roles:
                result.registrar = vcard.get("fn") or entity.get("handle")
                result.registrar_url = entity.get("url")

            if "registrant" in roles:
                result.registrant_name = vcard.get("fn")
                result.registrant_org = vcard.get("org")
                result.registrant_country = vcard.get("country")

        # Extract dates from events
        for event in data.get("events", []):
            event_action = event.get("eventAction")
            event_date = self._parse_date(event.get("eventDate"))

            if event_date:
                if event_action == "registration":
                    result.creation_date = event_date
                elif event_action == "last changed":
                    result.updated_date = event_date
                elif event_action == "expiration":
                    result.expiration_date = event_date

        # Extract status
        result.status = data.get("status", [])

        # Extract nameservers
        for ns in data.get("nameservers", []):
            ns_name = ns.get("ldhName")
            if ns_name:
                result.nameservers.append(ns_name)

        return result

    def _parse_ip_response(
        self,
        ip: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> RDAPResult:
        """Parse RDAP IP response."""
        result = RDAPResult(
            indicator_type=indicator_type,
            indicator_value=ip,
            raw_data=data,
            network_name=data.get("name"),
            network_handle=data.get("handle"),
        )

        # Extract CIDR
        start = data.get("startAddress")
        end = data.get("endAddress")
        if start:
            result.network_cidr = self._calculate_cidr(start, end)

        # Extract status
        result.status = data.get("status", [])

        # Extract entities
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = self._parse_vcard(entity.get("vcardArray", []))

            if "registrant" in roles or "administrative" in roles:
                result.registrant_name = vcard.get("fn")
                result.registrant_org = vcard.get("org")
                result.registrant_country = vcard.get("country")

        # Extract dates
        for event in data.get("events", []):
            event_action = event.get("eventAction")
            event_date = self._parse_date(event.get("eventDate"))

            if event_date:
                if event_action == "registration":
                    result.creation_date = event_date
                elif event_action == "last changed":
                    result.updated_date = event_date

        return result

    def _parse_vcard(self, vcard_array: list) -> dict[str, str]:
        """Parse jCard/vCard array format."""
        result: dict[str, str] = {}

        if not vcard_array or len(vcard_array) < 2:
            return result

        # vCard array format: ["vcard", [[property], [property], ...]]
        properties = vcard_array[1] if len(vcard_array) > 1 else []

        for prop in properties:
            if not isinstance(prop, list) or len(prop) < 4:
                continue

            prop_name = prop[0]
            prop_value = prop[3]

            if prop_name == "fn":
                result["fn"] = str(prop_value)
            elif prop_name == "org":
                if isinstance(prop_value, list):
                    result["org"] = str(prop_value[0]) if prop_value else ""
                else:
                    result["org"] = str(prop_value)
            elif prop_name == "adr":
                if isinstance(prop_value, list) and len(prop_value) > 6:
                    result["country"] = str(prop_value[6])

        return result

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO 8601 date string."""
        if not date_str:
            return None

        try:
            # Handle various ISO 8601 formats
            date_str = date_str.replace("Z", "+00:00")
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            try:
                # Try basic format
                return datetime.strptime(date_str[:10], "%Y-%m-%d")
            except Exception:
                return None

    def _calculate_cidr(
        self,
        start: Optional[str],
        end: Optional[str],
    ) -> Optional[str]:
        """Calculate CIDR notation from start/end addresses."""
        if not start:
            return None

        try:
            start_ip = ipaddress.ip_address(start)

            if end:
                end_ip = ipaddress.ip_address(end)
                # Calculate network from range
                network = ipaddress.summarize_address_range(start_ip, end_ip)
                return str(next(network))
            else:
                # Single IP
                if isinstance(start_ip, ipaddress.IPv4Address):
                    return f"{start}/32"
                else:
                    return f"{start}/128"

        except Exception:
            return start
