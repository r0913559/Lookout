"""Report generator."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from osint.core.config import Settings, get_settings, find_project_root
from osint.core.constants import IndicatorType, RiskLevel
from osint.models.reports import InvestigationReport, RelatedIndicator, TimelineEvent
from osint.orchestration.investigator import InvestigationResult


class ReportGenerator:
    """Generate reports from investigation results."""

    def __init__(self, settings: Optional[Settings] = None):
        """Initialize the report generator."""
        self.settings = settings or get_settings()

        # Set up Jinja2 environment
        template_dir = find_project_root() / "src" / "osint" / "reports" / "templates"
        if template_dir.exists():
            self.jinja_env = Environment(
                loader=FileSystemLoader(template_dir),
                autoescape=select_autoescape(["html", "xml"]),
            )
        else:
            self.jinja_env = None

    def create_report(
        self,
        result: InvestigationResult,
        analyst: Optional[str] = None,
    ) -> InvestigationReport:
        """
        Create an investigation report from results.

        Args:
            result: The investigation result
            analyst: Optional analyst name

        Returns:
            InvestigationReport
        """
        report = InvestigationReport(
            report_id=str(uuid.uuid4())[:8],
            analyst=analyst,
            indicator_value=result.indicator_value,
            indicator_type=result.indicator_type,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            sources_queried=[s.value for s in result.sources_queried],
            sources_with_data=[
                s.value for s, r in result.results.items() if r and r.success
            ],
        )

        # Generate risk summary
        report.risk_summary = report.generate_risk_summary()

        # Extract key findings
        report.key_findings = self._extract_key_findings(result)

        # Build timeline
        self._build_timeline(report, result)

        # Extract related indicators
        self._extract_related(report, result)

        # Generate executive summary
        report.executive_summary = self._generate_executive_summary(report)

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        return report

    def _extract_key_findings(self, result: InvestigationResult) -> list[str]:
        """Extract key findings from results."""
        from osint.models.results import (
            VirusTotalResult, URLScanResult, AbuseIPDBResult, ShodanResult,
            ThreatFoxResult, URLhausResult, CrtshResult,
        )

        findings = []

        for source, api_result in result.results.items():
            if not api_result or not api_result.success:
                continue

            # VirusTotal findings
            if isinstance(api_result, VirusTotalResult):
                mal = api_result.malicious or 0
                total = api_result.total_scanners or 0
                if mal > 0 and total > 0:
                    findings.append(
                        f"VirusTotal: {mal}/{total} scanners flagged as malicious"
                    )
                if api_result.categories:
                    cats = list(api_result.categories.values())[:2]
                    findings.append(f"VirusTotal categories: {', '.join(cats)}")

            # URLScan findings
            elif isinstance(api_result, URLScanResult):
                if api_result.malicious:
                    findings.append("URLScan: Flagged as malicious")
                if api_result.page_title and api_result.page_title != "404 Not Found":
                    findings.append(f"URLScan: Page title \"{api_result.page_title}\"")

            # AbuseIPDB findings
            elif isinstance(api_result, AbuseIPDBResult):
                score = api_result.abuse_confidence_score
                if score > 50:
                    findings.append(
                        f"AbuseIPDB: {score}% abuse confidence score"
                    )
                if api_result.total_reports and api_result.total_reports > 0:
                    findings.append(
                        f"AbuseIPDB: {api_result.total_reports} abuse reports"
                    )

            # ThreatFox findings
            elif isinstance(api_result, ThreatFoxResult):
                if api_result.total_matches > 0:
                    families = api_result.malware_families or []
                    if families:
                        findings.append(
                            f"ThreatFox: Associated with malware families: "
                            f"{', '.join(families[:3])}"
                        )
                    else:
                        findings.append(
                            f"ThreatFox: {api_result.total_matches} IOC matches found"
                        )

            # URLhaus findings
            elif isinstance(api_result, URLhausResult):
                if api_result.threat:
                    findings.append(
                        f"URLhaus: Classified as {api_result.threat}"
                    )

            # Shodan findings
            elif isinstance(api_result, ShodanResult):
                if api_result.vulns:
                    findings.append(
                        f"Shodan: {len(api_result.vulns)} known vulnerabilities"
                    )
                if api_result.ports:
                    findings.append(
                        f"Shodan: Open ports: {', '.join(map(str, api_result.ports[:5]))}"
                    )

            # crt.sh findings
            elif isinstance(api_result, CrtshResult):
                if api_result.subdomains and len(api_result.subdomains) > 5:
                    findings.append(
                        f"crt.sh: {len(api_result.subdomains)} subdomains found in certificates"
                    )

        # Add general finding if clean
        if not findings and result.risk_level == RiskLevel.CLEAN:
            findings.append("No malicious indicators detected across all sources")

        return findings

    def _build_timeline(
        self,
        report: InvestigationReport,
        result: InvestigationResult,
    ) -> None:
        """Build timeline from results."""
        from osint.models.results import (
            VirusTotalResult, RDAPResult, ThreatFoxResult, URLhausResult,
        )

        for source, api_result in result.results.items():
            if not api_result or not api_result.success:
                continue

            # RDAP/VT registration dates
            if isinstance(api_result, (RDAPResult, VirusTotalResult)):
                if api_result.creation_date:
                    report.add_timeline_event(
                        source=source.value,
                        event_type="registered",
                        description="Domain/Resource first registered",
                        timestamp=api_result.creation_date,
                    )

            # VirusTotal last analysis
            if isinstance(api_result, VirusTotalResult):
                if api_result.last_analysis_date:
                    report.add_timeline_event(
                        source=source.value,
                        event_type="scanned",
                        description=f"Last scanned by {source.value}",
                        timestamp=api_result.last_analysis_date,
                    )

            # ThreatFox dates
            if isinstance(api_result, ThreatFoxResult):
                if api_result.first_seen:
                    report.add_timeline_event(
                        source=source.value,
                        event_type="first_seen",
                        description="First seen in ThreatFox",
                        timestamp=api_result.first_seen,
                    )

            # URLhaus dates
            if isinstance(api_result, URLhausResult):
                if api_result.date_added:
                    report.add_timeline_event(
                        source=source.value,
                        event_type="added",
                        description="Added to URLhaus database",
                        timestamp=api_result.date_added,
                    )

    def _extract_related(
        self,
        report: InvestigationReport,
        result: InvestigationResult,
    ) -> None:
        """Extract related indicators from results."""
        from osint.models.results import (
            CrtshResult, ShodanResult, AlienVaultResult,
        )

        for source, api_result in result.results.items():
            if not api_result or not api_result.success:
                continue

            # Crt.sh subdomains
            if isinstance(api_result, CrtshResult):
                for subdomain in (api_result.subdomains or [])[:10]:
                    report.add_related_indicator(
                        value=subdomain,
                        indicator_type=IndicatorType.DOMAIN,
                        relationship="subdomain_of",
                        source=source.value,
                        confidence=0.9,
                    )

            # Shodan hostnames
            if isinstance(api_result, ShodanResult):
                for hostname in (api_result.hostnames or [])[:5]:
                    report.add_related_indicator(
                        value=hostname,
                        indicator_type=IndicatorType.DOMAIN,
                        relationship="resolves_to",
                        source=source.value,
                        confidence=0.8,
                    )

            # AlienVault related
            if isinstance(api_result, AlienVaultResult):
                for domain in (api_result.related_domains or [])[:5]:
                    report.add_related_indicator(
                        value=domain,
                        indicator_type=IndicatorType.DOMAIN,
                        relationship="related",
                        source=source.value,
                        confidence=0.6,
                    )

    def _generate_executive_summary(self, report: InvestigationReport) -> str:
        """Generate executive summary."""
        lines = [
            f"Investigation of {report.indicator_type.value} indicator: "
            f"{report.indicator_value}",
            "",
            report.risk_summary or "",
            "",
            f"Data was collected from {len(report.sources_with_data)} of "
            f"{len(report.sources_queried)} queried sources.",
        ]

        if report.key_findings:
            lines.append("")
            lines.append("Key findings include:")
            for finding in report.key_findings[:5]:
                lines.append(f"- {finding}")

        return "\n".join(lines)

    def _generate_recommendations(self, report: InvestigationReport) -> list[str]:
        """Generate recommendations based on risk level."""
        recs = []

        if report.risk_level == RiskLevel.CRITICAL:
            recs.extend([
                "Immediately block this indicator at network perimeter",
                "Search for historical connections in logs",
                "Conduct incident response if connections found",
                "Report to relevant threat intelligence sharing groups",
            ])
        elif report.risk_level == RiskLevel.HIGH:
            recs.extend([
                "Consider blocking this indicator",
                "Add to watchlist for monitoring",
                "Investigate any connections from internal systems",
            ])
        elif report.risk_level == RiskLevel.MEDIUM:
            recs.extend([
                "Add to monitoring watchlist",
                "Investigate if connections are from critical systems",
                "Consider additional sandboxing if file hash",
            ])
        elif report.risk_level == RiskLevel.LOW:
            recs.extend([
                "Continue monitoring",
                "No immediate action required",
            ])
        else:
            recs.extend([
                "Gather additional intelligence",
                "Monitor for future reports",
            ])

        return recs

    def to_markdown(self, report: InvestigationReport) -> str:
        """Render report as Markdown."""
        if self.jinja_env:
            try:
                template = self.jinja_env.get_template("report.md.j2")
                return template.render(report=report)
            except Exception:
                pass

        # Fallback to manual rendering
        lines = [
            f"# Investigation Report: {report.indicator_value}",
            "",
            f"**Report ID:** {report.report_id}",
            f"**Generated:** {report.created_at.isoformat()}",
            f"**Analyst:** {report.analyst or 'N/A'}",
            "",
            "## Executive Summary",
            "",
            report.executive_summary,
            "",
            "## Risk Assessment",
            "",
            f"- **Risk Level:** {report.risk_level.value.upper()}",
            f"- **Risk Score:** {report.risk_score:.0f}/100" if report.risk_score else "",
            "",
            report.risk_summary or "",
            "",
            "## Key Findings",
            "",
        ]

        for finding in report.key_findings:
            lines.append(f"- {finding}")

        lines.extend([
            "",
            "## Recommendations",
            "",
        ])

        for rec in report.recommendations:
            lines.append(f"- {rec}")

        if report.timeline:
            lines.extend([
                "",
                "## Timeline",
                "",
                "| Date | Source | Event | Description |",
                "|------|--------|-------|-------------|",
            ])
            for event in report.timeline:
                lines.append(
                    f"| {event.timestamp.strftime('%Y-%m-%d')} | "
                    f"{event.source} | {event.event_type} | {event.description} |"
                )

        if report.related_indicators:
            lines.extend([
                "",
                "## Related Indicators",
                "",
            ])
            for rel in report.related_indicators[:20]:
                lines.append(f"- **{rel.indicator_type.value}:** {rel.value} ({rel.relationship})")

        lines.extend([
            "",
            "---",
            "*Generated by OSINT Tool*",
        ])

        return "\n".join(lines)

    def to_json(self, report: InvestigationReport) -> str:
        """Render report as JSON."""
        return report.model_dump_json(indent=2)

    def save_report(
        self,
        report: InvestigationReport,
        output_path: Path,
        format: str = "markdown",
    ) -> Path:
        """
        Save report to file.

        Args:
            report: The report to save
            output_path: Output file path
            format: Output format (markdown, json)

        Returns:
            Path to saved file
        """
        if format == "json":
            content = self.to_json(report)
            if not output_path.suffix:
                output_path = output_path.with_suffix(".json")
        else:
            content = self.to_markdown(report)
            if not output_path.suffix:
                output_path = output_path.with_suffix(".md")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)

        return output_path
