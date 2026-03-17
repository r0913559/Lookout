"""URLScan.io API client."""

from datetime import datetime
from typing import Any, Optional

from osint.clients.base import BaseAPIClient
from osint.core.constants import APISource, IndicatorType
from osint.models.results import URLScanResult


class URLScanClient(BaseAPIClient[URLScanResult]):
    """
    URLScan.io API client.

    Provides URL scanning and website analysis.
    """

    name = "urlscan"
    base_url = "https://urlscan.io/api/v1"
    requires_auth = True
    source = APISource.URLSCAN

    def _get_auth_headers(self) -> dict[str, str]:
        """Get URLScan authentication headers."""
        api_key = self.settings.get_api_key("urlscan")
        if api_key:
            return {"API-Key": api_key}
        return {}

    def supports_indicator(self, indicator_type: IndicatorType) -> bool:
        """URLScan supports domains and URLs."""
        return indicator_type in (
            IndicatorType.DOMAIN,
            IndicatorType.URL,
        )

    async def lookup(
        self,
        value: str,
        indicator_type: IndicatorType,
    ) -> Optional[URLScanResult]:
        """Search URLScan for existing scans of an indicator."""
        try:
            if indicator_type == IndicatorType.DOMAIN:
                return await self._search_domain(value)
            elif indicator_type == IndicatorType.URL:
                return await self._search_url(value)
            else:
                return None
        except Exception as e:
            self.logger.error(f"URLScan lookup failed for {value}: {e}")
            return URLScanResult(
                indicator_type=indicator_type,
                indicator_value=value,
                success=False,
                error_message=str(e),
            )

    async def _search_domain(self, domain: str) -> URLScanResult:
        """Search for scans of a domain."""
        params = {"q": f"domain:{domain}"}
        data = await self._request("GET", "/search/", params=params)
        return self._parse_search_response(domain, IndicatorType.DOMAIN, data)

    async def _search_url(self, url: str) -> URLScanResult:
        """Search for scans of a URL."""
        params = {"q": f"page.url:{url}"}
        data = await self._request("GET", "/search/", params=params)
        return self._parse_search_response(url, IndicatorType.URL, data)

    def _parse_search_response(
        self,
        value: str,
        indicator_type: IndicatorType,
        data: dict[str, Any],
    ) -> URLScanResult:
        """Parse URLScan search response."""
        result = URLScanResult(
            indicator_type=indicator_type,
            indicator_value=value,
            raw_data=data,
        )

        results = data.get("results", [])

        if not results:
            return result

        # Use most recent scan
        latest = results[0]
        task = latest.get("task", {})
        page = latest.get("page", {})
        stats = latest.get("stats", {})

        result.scan_id = latest.get("_id")
        result.scan_url = task.get("url")
        result.result_url = latest.get("result")
        result.screenshot_url = latest.get("screenshot")

        # Page info
        result.page_title = page.get("title")
        result.page_ip = page.get("ip")
        result.page_country = page.get("country")
        result.page_server = page.get("server")
        result.page_asn = page.get("asn")

        # Verdicts
        verdicts = latest.get("verdicts", {})
        overall = verdicts.get("overall", {})
        result.malicious = overall.get("malicious", False)
        result.score = overall.get("score", 0)
        result.categories = overall.get("categories", [])
        result.brands = overall.get("brands", [])

        # Calculate risk score
        if result.malicious:
            result.risk_score = max(70, result.score)
        else:
            result.risk_score = min(result.score, 30)
        result.calculate_risk_level()

        return result

    async def submit_scan(
        self,
        url: str,
        visibility: str = "public",
        tags: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Submit a URL for scanning.

        Args:
            url: URL to scan
            visibility: "public", "unlisted", or "private"
            tags: Optional tags for the scan

        Returns:
            Submission response with scan UUID
        """
        payload = {
            "url": url,
            "visibility": visibility,
        }
        if tags:
            payload["tags"] = tags

        return await self._request("POST", "/scan/", json_data=payload)

    async def get_scan_result(self, scan_uuid: str) -> dict[str, Any]:
        """Get results of a completed scan."""
        return await self._request("GET", f"/result/{scan_uuid}/")

    async def get_screenshot(self, scan_uuid: str) -> str:
        """Get screenshot URL for a scan."""
        return f"https://urlscan.io/screenshots/{scan_uuid}.png"
