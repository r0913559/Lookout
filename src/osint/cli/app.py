"""Main CLI application using Typer."""

import asyncio
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.markdown import Markdown

from osint.cache.manager import CacheManager
from osint.core.config import get_settings, reload_settings
from osint.core.constants import APISource, IndicatorType, OutputFormat, RiskLevel
from osint.core.exceptions import DetectionError, OSINTError
from osint.detection.indicator_type import detect_indicator_type
from osint.orchestration.investigator import Investigator, InvestigationResult
from osint.orchestration.correlator import InfrastructureCorrelator
from osint.reports.generator import ReportGenerator

# Initialize Typer app
app = typer.Typer(
    name="lookout",
    help="Lookout - Automated OSINT & Threat Intelligence Investigation Tool",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()

# Subcommands
cache_app = typer.Typer(help="Cache management commands")
config_app = typer.Typer(help="Configuration commands")
app.add_typer(cache_app, name="cache")
app.add_typer(config_app, name="config")


# ---------------------------------------------------------------------------
# Risk display helpers
# ---------------------------------------------------------------------------

RISK_COLORS = {
    RiskLevel.UNKNOWN: "dim",
    RiskLevel.CLEAN: "green",
    RiskLevel.LOW: "blue",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bold red",
}

RISK_ICONS = {
    RiskLevel.UNKNOWN: "?",
    RiskLevel.CLEAN: "V",
    RiskLevel.LOW: "~",
    RiskLevel.MEDIUM: "!",
    RiskLevel.HIGH: "!!",
    RiskLevel.CRITICAL: "!!!",
}

RISK_LABELS = {
    RiskLevel.UNKNOWN: "Unknown - not enough data",
    RiskLevel.CLEAN: "Clean - no threats detected",
    RiskLevel.LOW: "Low risk - minor flags, probably safe",
    RiskLevel.MEDIUM: "Medium risk - suspicious, investigate further",
    RiskLevel.HIGH: "High risk - likely malicious",
    RiskLevel.CRITICAL: "Critical - confirmed malicious",
}


def get_risk_color(risk_level: RiskLevel) -> str:
    return RISK_COLORS.get(risk_level, "white")


def format_risk_badge(risk_level: RiskLevel, risk_score: Optional[float]) -> Text:
    color = get_risk_color(risk_level)
    icon = RISK_ICONS.get(risk_level, "?")
    score_str = f" {risk_score:.0f}/100" if risk_score is not None else ""
    return Text(f"[{icon}] {risk_level.value.upper()}{score_str}", style=color)


# ---------------------------------------------------------------------------
# Rich output: table view (source-by-source overview)
# ---------------------------------------------------------------------------

def _safe_get(obj, field: str, default=None):
    """Safely get a field from a Pydantic model without triggering AttributeError."""
    try:
        return getattr(obj, field, default)
    except (AttributeError, Exception):
        return default


def _get_result_details(api_result) -> str:
    """Extract key details from an API result based on its type."""
    from osint.models.results import (
        VirusTotalResult, URLScanResult, AbuseIPDBResult, ShodanResult,
        RDAPResult, CrtshResult, ThreatFoxResult, URLhausResult,
        AlienVaultResult,
    )

    details = []

    if isinstance(api_result, VirusTotalResult):
        total = api_result.total_scanners or 0
        mal = api_result.malicious or 0
        sus = api_result.suspicious or 0
        if total > 0:
            details.append(f"{mal}/{total} malicious")
            if sus > 0:
                details.append(f"{sus} suspicious")

    elif isinstance(api_result, URLScanResult):
        if api_result.malicious:
            details.append("Malicious")
        if api_result.page_ip:
            details.append(f"IP: {api_result.page_ip}")
        if api_result.page_title:
            details.append(f'"{api_result.page_title}"')

    elif isinstance(api_result, AbuseIPDBResult):
        if api_result.abuse_confidence_score > 0:
            details.append(f"Confidence: {api_result.abuse_confidence_score}%")
        if api_result.total_reports:
            details.append(f"{api_result.total_reports} reports")
        if api_result.isp:
            details.append(f"ISP: {api_result.isp}")

    elif isinstance(api_result, ShodanResult):
        if api_result.ports:
            details.append(f"Ports: {', '.join(map(str, api_result.ports[:5]))}")
        if api_result.vulns:
            details.append(f"CVEs: {len(api_result.vulns)}")
        if api_result.org:
            details.append(f"Org: {api_result.org}")

    elif isinstance(api_result, RDAPResult):
        if api_result.registrar:
            details.append(f"Registrar: {api_result.registrar}")
        if api_result.creation_date:
            details.append(f"Created: {api_result.creation_date.strftime('%Y-%m-%d')}")
        if api_result.nameservers:
            details.append(f"NS: {', '.join(api_result.nameservers[:2])}")

    elif isinstance(api_result, CrtshResult):
        if api_result.subdomains:
            details.append(f"{len(api_result.subdomains)} subdomains")
        if api_result.total_certificates:
            details.append(f"{api_result.total_certificates} certs")

    elif isinstance(api_result, ThreatFoxResult):
        if api_result.total_matches > 0:
            details.append(f"{api_result.total_matches} matches")
        if api_result.malware_families:
            details.append(f"Malware: {', '.join(api_result.malware_families[:2])}")

    elif isinstance(api_result, URLhausResult):
        if api_result.url_status:
            details.append(f"Status: {api_result.url_status}")
        if api_result.threat:
            details.append(f"Threat: {api_result.threat}")

    elif isinstance(api_result, AlienVaultResult):
        if api_result.pulse_count > 0:
            details.append(f"{api_result.pulse_count} pulses")

    return ", ".join(details) if details else "-"


def print_source_table(result: InvestigationResult) -> None:
    """Print the per-source results table."""
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Source", style="cyan", min_width=12)
    table.add_column("Status", min_width=10)
    table.add_column("Risk", min_width=14)
    table.add_column("Details")

    for source in result.sources_queried:
        api_result = result.results.get(source)

        if api_result is None:
            table.add_row(source.value, Text("Failed", style="red"), "-", "-")
        elif not api_result.success:
            table.add_row(
                source.value,
                Text("Error", style="red"),
                "-",
                api_result.error_message or "Unknown error",
            )
        else:
            cached_tag = " [cached]" if api_result.cached else ""
            status = Text(f"OK{cached_tag}", style="green")

            if api_result.risk_score is not None:
                risk_color = get_risk_color(api_result.risk_level)
                risk = Text(
                    f"{api_result.risk_level.value} ({api_result.risk_score:.0f})",
                    style=risk_color,
                )
            else:
                risk = Text("-", style="dim")

            details = _get_result_details(api_result)
            table.add_row(source.value, status, risk, details)

    console.print(table)


# ---------------------------------------------------------------------------
# Rich output: assessment panel (what does this mean?)
# ---------------------------------------------------------------------------

def print_assessment(report) -> None:
    """Print a human-readable assessment panel."""
    risk_color = get_risk_color(report.risk_level)
    label = RISK_LABELS.get(report.risk_level, "")

    # Risk assessment box
    assessment_lines = []
    assessment_lines.append(f"[{risk_color}]{label}[/{risk_color}]")
    if report.risk_summary:
        assessment_lines.append("")
        assessment_lines.append(report.risk_summary)

    console.print()
    console.print(Panel(
        "\n".join(assessment_lines),
        title="[bold]Assessment[/bold]",
        border_style=risk_color,
        padding=(1, 2),
    ))

    # Key findings
    if report.key_findings:
        console.print()
        console.print("[bold]Key findings:[/bold]")
        for finding in report.key_findings:
            console.print(f"  - {finding}")

    # Recommendations
    if report.recommendations:
        console.print()
        console.print("[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            console.print(f"  - {rec}")


# ---------------------------------------------------------------------------
# Rich output: timeline
# ---------------------------------------------------------------------------

def print_timeline(report) -> None:
    """Print timeline events if any exist."""
    if not report.timeline:
        return

    console.print()
    console.print("[bold]Timeline:[/bold]")
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Date", style="cyan", min_width=12)
    table.add_column("Source", min_width=12)
    table.add_column("Event")

    for event in report.timeline:
        table.add_row(
            event.timestamp.strftime("%Y-%m-%d"),
            event.source,
            event.description,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Rich output: pivot suggestions
# ---------------------------------------------------------------------------

def print_pivot_suggestions(result: InvestigationResult) -> None:
    """Extract and display pivot suggestions from investigation results."""
    from osint.models.results import (
        VirusTotalResult, URLScanResult, AbuseIPDBResult, ShodanResult,
        RDAPResult, CrtshResult, ThreatFoxResult, URLhausResult,
        AlienVaultResult,
    )

    pivots: list[tuple[str, str, str, str, float]] = []
    # (type_label, value, relationship, source, confidence)

    seen_values: set[str] = set()
    seen_values.add(result.indicator_value.lower())

    for source, api_result in result.results.items():
        if not api_result or not api_result.success:
            continue

        # URLScan: hosting IP
        if isinstance(api_result, URLScanResult) and api_result.page_ip:
            ip = api_result.page_ip
            if ip.lower() not in seen_values:
                pivots.append(("IP", ip, "hosted on", source.value, 0.9))
                seen_values.add(ip.lower())

        # Shodan: hostnames and domains
        if isinstance(api_result, ShodanResult):
            for hostname in (api_result.hostnames or [])[:5]:
                if hostname.lower() not in seen_values:
                    pivots.append(("DOMAIN", hostname, "reverse DNS", source.value, 0.85))
                    seen_values.add(hostname.lower())
            for domain in (api_result.domains or [])[:5]:
                if domain.lower() not in seen_values:
                    pivots.append(("DOMAIN", domain, "associated domain", source.value, 0.7))
                    seen_values.add(domain.lower())

        # RDAP: nameservers and CIDR
        if isinstance(api_result, RDAPResult):
            for ns in (api_result.nameservers or [])[:3]:
                if ns.lower() not in seen_values:
                    pivots.append(("DOMAIN", ns, "nameserver", source.value, 0.6))
                    seen_values.add(ns.lower())
            if api_result.network_cidr:
                cidr = api_result.network_cidr
                if cidr.lower() not in seen_values:
                    pivots.append(("CIDR", cidr, "IP range", source.value, 0.5))
                    seen_values.add(cidr.lower())

        # crt.sh: interesting subdomains
        if isinstance(api_result, CrtshResult) and api_result.subdomains:
            interesting_prefixes = (
                "admin", "cpanel", "mail", "webmail", "api", "staging",
                "dev", "test", "vpn", "remote", "ftp", "login", "portal",
                "panel", "cms", "app", "dashboard",
            )
            subs = api_result.subdomains or []
            interesting = [s for s in subs if any(
                s.lower().startswith(p + ".") for p in interesting_prefixes
            )]
            others = [s for s in subs if s not in interesting
                       and not s.startswith("*.")
                       and s.lower() not in seen_values]

            for sub in (interesting + others)[:8]:
                if sub.lower() not in seen_values:
                    tag = "notable subdomain" if sub in interesting else "subdomain"
                    pivots.append(("DOMAIN", sub, tag, source.value, 0.95))
                    seen_values.add(sub.lower())

        # VirusTotal: ASN info
        if isinstance(api_result, VirusTotalResult) and api_result.asn:
            as_owner = api_result.as_owner or ""
            asn_label = f"AS{api_result.asn}"
            if as_owner:
                asn_label += f" ({as_owner})"
            if asn_label.lower() not in seen_values:
                pivots.append(("ASN", asn_label, "network owner", source.value, 0.4))
                seen_values.add(asn_label.lower())

        # AbuseIPDB: ISP/domain
        if isinstance(api_result, AbuseIPDBResult) and api_result.domain:
            d = api_result.domain
            if d.lower() not in seen_values:
                pivots.append(("DOMAIN", d, "ISP domain", source.value, 0.3))
                seen_values.add(d.lower())

        # ThreatFox: malware families
        if isinstance(api_result, ThreatFoxResult) and api_result.malware_families:
            for family in (api_result.malware_families or [])[:3]:
                if family.lower() not in seen_values:
                    pivots.append(("MALWARE", family, "malware family", source.value, 0.8))
                    seen_values.add(family.lower())

        # AlienVault: related indicators
        if isinstance(api_result, AlienVaultResult):
            for d in (api_result.related_domains or [])[:5]:
                if d.lower() not in seen_values:
                    pivots.append(("DOMAIN", d, "threat related", source.value, 0.6))
                    seen_values.add(d.lower())
        if hasattr(api_result, "related_ips"):
            for ip in (api_result.related_ips or [])[:5]:
                if ip.lower() not in seen_values:
                    pivots.append(("IP", ip, "threat related", source.value, 0.6))
                    seen_values.add(ip.lower())

    if not pivots:
        return

    # Sort by confidence descending
    pivots.sort(key=lambda p: p[4], reverse=True)

    # Limit to top 15
    pivots = pivots[:15]

    console.print()
    console.print(Rule("Pivot suggestions", style="bold cyan"))
    console.print(
        "[dim]Indicators found during this investigation that may be worth looking into.[/dim]"
    )
    console.print()

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Type", style="bold", min_width=8)
    table.add_column("Value", style="cyan")
    table.add_column("Relation", style="dim")
    table.add_column("Source", style="dim")
    table.add_column("Conf.", justify="right", min_width=5)

    for type_label, value, relationship, source, confidence in pivots:
        conf_color = "green" if confidence >= 0.8 else "yellow" if confidence >= 0.5 else "dim"
        table.add_row(
            type_label,
            value,
            relationship,
            source,
            Text(f"{confidence * 100:.0f}%", style=conf_color),
        )

    console.print(table)

    # Show a helpful tip for the top pivot
    top_type, top_value, _, _, _ = pivots[0]
    if top_type in ("DOMAIN", "IP"):
        console.print(
            f"\n[dim]Tip: run [bold]lookout investigate {top_value}[/bold] "
            f"to pivot further[/dim]"
        )


# ---------------------------------------------------------------------------
# Rich output: verbose details
# ---------------------------------------------------------------------------

def print_verbose_details(result: InvestigationResult) -> None:
    """Print verbose per-source details."""
    for source, api_result in result.results.items():
        if api_result and api_result.success:
            console.print(f"\n[bold cyan]{source.value}[/bold cyan] details:")
            data = api_result.model_dump(exclude={"raw_data", "cached"})
            for key, value in data.items():
                if value is not None and key not in (
                    "source", "indicator_type", "indicator_value",
                    "timestamp", "success",
                ):
                    console.print(f"  {key}: {value}")


# ---------------------------------------------------------------------------
# Quota status display
# ---------------------------------------------------------------------------

def _print_quota_status(sources_queried: list = None) -> None:
    """Print daily API quota usage for queried sources."""
    settings = get_settings()
    cache = CacheManager(settings)
    usage = cache.get_all_daily_usage()
    cache.close()

    quota_warnings = []
    quota_info = []

    sources_to_check = set()
    if sources_queried:
        for s in sources_queried:
            sources_to_check.add(s.value if hasattr(s, "value") else str(s))
    else:
        sources_to_check = set(usage.keys())

    # Also include any source with a configured quota
    for api_name, quota in settings.daily_quotas.items():
        if quota > 0:
            sources_to_check.add(api_name)

    for source_name in sorted(sources_to_check):
        quota = settings.get_daily_quota(source_name)
        if quota <= 0:
            continue

        used = usage.get(source_name, 0)
        remaining = quota - used
        tier = settings.get_api_tier(source_name)
        tier_tag = f" [{tier}]" if tier == "premium" else ""

        if remaining <= 0:
            quota_warnings.append(
                f"[bold red]{source_name}{tier_tag}: QUOTA REACHED "
                f"({used}/{quota} today)[/bold red]"
            )
        elif remaining <= quota * 0.1:  # Less than 10% remaining
            quota_warnings.append(
                f"[yellow]{source_name}{tier_tag}: {remaining} remaining "
                f"({used}/{quota} today)[/yellow]"
            )
        elif used > 0:
            quota_info.append(f"{source_name}{tier_tag}: {used}/{quota}")

    if quota_warnings:
        console.print()
        for w in quota_warnings:
            console.print(f"  {w}")

    if quota_info:
        console.print(f"[dim]  Quota: {' | '.join(quota_info)}[/dim]")


# ---------------------------------------------------------------------------
# Full table output (combines everything)
# ---------------------------------------------------------------------------

def print_investigation_result(result: InvestigationResult, verbose: bool = False) -> None:
    """Print full investigation result to console."""
    # Generate rich report
    report_gen = ReportGenerator()
    report = report_gen.create_report(result)

    # --- Header ---
    risk_badge = format_risk_badge(result.risk_level, result.risk_score)
    header = Text()
    header.append(f"\n{result.indicator_type.value.upper()}: ", style="bold")
    header.append(result.indicator_value, style="cyan bold")
    header.append("  ")
    header.append_text(risk_badge)
    console.print(header)

    # --- Source results table ---
    console.print()
    print_source_table(result)

    # --- Assessment (what does this mean?) ---
    print_assessment(report)

    # --- Timeline ---
    print_timeline(report)

    # --- Pivot suggestions ---
    print_pivot_suggestions(result)

    # --- Verbose ---
    if verbose:
        print_verbose_details(result)

    # --- Footer with quota info ---
    footer_parts = [
        f"Queried {len(result.sources_queried)} sources in "
        f"{result.duration_seconds:.2f}s "
        f"({len(result.cached_sources)} cached)"
    ]
    console.print(f"\n[dim]{footer_parts[0]}[/dim]")

    # Show daily quota usage
    _print_quota_status(result.sources_queried)


# ---------------------------------------------------------------------------
# Markdown output (uses ReportGenerator + pivot section)
# ---------------------------------------------------------------------------

def output_markdown(result: InvestigationResult, output_path: Optional[Path] = None) -> None:
    """Output result as full Markdown report."""
    report_gen = ReportGenerator()
    report = report_gen.create_report(result)
    md_content = report_gen.to_markdown(report)

    # Append pivot suggestions
    pivots_md = _generate_pivot_markdown(result)
    if pivots_md:
        md_content += "\n" + pivots_md

    # Replace footer
    md_content = md_content.replace("*Generated by OSINT Tool*", "*Generated by Lookout*")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(md_content)
        console.print(f"[green]Report written to {output_path}[/green]")
    else:
        console.print(md_content)


def _generate_pivot_markdown(result: InvestigationResult) -> str:
    """Generate pivot suggestions as Markdown."""
    from osint.models.results import (
        VirusTotalResult, URLScanResult, ShodanResult,
        RDAPResult, CrtshResult, ThreatFoxResult, AlienVaultResult,
    )

    pivots: list[tuple[str, str, str, str, float]] = []
    seen: set[str] = {result.indicator_value.lower()}

    for source, api_result in result.results.items():
        if not api_result or not api_result.success:
            continue

        if isinstance(api_result, URLScanResult) and api_result.page_ip:
            ip = api_result.page_ip
            if ip.lower() not in seen:
                pivots.append(("IP", ip, "hosted on", source.value, 0.9))
                seen.add(ip.lower())

        if isinstance(api_result, ShodanResult):
            for h in (api_result.hostnames or [])[:5]:
                if h.lower() not in seen:
                    pivots.append(("DOMAIN", h, "reverse DNS", source.value, 0.85))
                    seen.add(h.lower())

        if isinstance(api_result, CrtshResult):
            for s in (api_result.subdomains or [])[:8]:
                if s.lower() not in seen and not s.startswith("*."):
                    pivots.append(("DOMAIN", s, "subdomain", source.value, 0.95))
                    seen.add(s.lower())

        if isinstance(api_result, RDAPResult):
            for ns in (api_result.nameservers or [])[:3]:
                if ns.lower() not in seen:
                    pivots.append(("DOMAIN", ns, "nameserver", source.value, 0.6))
                    seen.add(ns.lower())

        if isinstance(api_result, ThreatFoxResult):
            for f in (api_result.malware_families or [])[:3]:
                if f.lower() not in seen:
                    pivots.append(("MALWARE", f, "malware family", source.value, 0.8))
                    seen.add(f.lower())

    if not pivots:
        return ""

    pivots.sort(key=lambda p: p[4], reverse=True)
    pivots = pivots[:15]

    lines = [
        "## Pivot Suggestions",
        "",
        "Indicators found during this investigation that may be worth investigating further.",
        "",
        "| Type | Value | Relation | Source | Confidence |",
        "|------|-------|----------|--------|------------|",
    ]
    for type_label, value, rel, src, conf in pivots:
        lines.append(f"| {type_label} | `{value}` | {rel} | {src} | {conf*100:.0f}% |")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON output (enriched with pivots)
# ---------------------------------------------------------------------------

def output_json(result: InvestigationResult, output_path: Optional[Path] = None) -> None:
    """Output result as JSON, enriched with report data and pivots."""
    report_gen = ReportGenerator()
    report = report_gen.create_report(result)

    data = result.to_dict()

    # Add report fields
    data["assessment"] = {
        "risk_summary": report.risk_summary,
        "key_findings": report.key_findings,
        "recommendations": report.recommendations,
        "executive_summary": report.executive_summary,
    }

    # Add timeline
    data["timeline"] = [
        {
            "date": event.timestamp.isoformat(),
            "source": event.source,
            "event_type": event.event_type,
            "description": event.description,
        }
        for event in report.timeline
    ]

    # Add related/pivot indicators
    data["pivot_indicators"] = [
        {
            "value": rel.value,
            "type": rel.indicator_type.value,
            "relationship": rel.relationship,
            "source": rel.source,
            "confidence": rel.confidence,
        }
        for rel in report.related_indicators
    ]

    json_str = json.dumps(data, indent=2, default=str)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str)
        console.print(f"[green]Output written to {output_path}[/green]")
    else:
        console.print(json_str)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@app.command()
def investigate(
    value: str = typer.Argument(..., help="Indicator to investigate (domain, IP, hash, or URL)"),
    format: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--format",
        "-f",
        help="Output format",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Bypass cache for fresh results",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output per source",
    ),
) -> None:
    """
    Investigate an indicator (domain, IP, hash, or URL).

    Examples:
        lookout investigate google.com
        lookout investigate 1.2.3.4
        lookout investigate abc123...def456
        lookout investigate https://suspicious-site.com
    """
    # Detect indicator type
    try:
        indicator_type = detect_indicator_type(value)
    except DetectionError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"[dim]Detected type: {indicator_type.value}[/dim]")

    # Run investigation
    async def run_investigation() -> InvestigationResult:
        async with Investigator(use_cache=not no_cache) as investigator:
            return await investigator.investigate(value, indicator_type)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Investigating...", total=None)

        try:
            result = asyncio.run(run_investigation())
        except OSINTError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

    # Output results
    if format == OutputFormat.JSON:
        output_json(result, output)
    elif format == OutputFormat.MARKDOWN:
        output_markdown(result, output)
    else:
        print_investigation_result(result, verbose=verbose)
        if output:
            output_json(result, output)


@app.command()
def detect(
    value: str = typer.Argument(..., help="Value to detect type of"),
) -> None:
    """Detect the type of an indicator."""
    try:
        indicator_type = detect_indicator_type(value)
        console.print(f"[green]Detected:[/green] {indicator_type.value}")
    except DetectionError as e:
        console.print(f"[red]Could not detect type:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def enumerate(
    domain: str = typer.Argument(..., help="Domain to enumerate subdomains for"),
    wordlist: Optional[Path] = typer.Option(
        None,
        "--wordlist",
        "-w",
        help="Custom wordlist file (default: built-in phishing-enriched list)",
    ),
    concurrency: int = typer.Option(
        50,
        "--concurrency",
        "-c",
        help="Max parallel DNS queries",
    ),
    timeout: float = typer.Option(
        3.0,
        "--timeout",
        "-t",
        help="Timeout per DNS query in seconds",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save results to file (JSON)",
    ),
    with_crtsh: bool = typer.Option(
        True,
        "--crtsh/--no-crtsh",
        help="Also fetch subdomains from crt.sh certificate transparency",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the OPSEC warning confirmation",
    ),
) -> None:
    """
    Enumerate subdomains for a domain using DNS brute-force + crt.sh.

    WARNING: This command sends DNS queries that may be visible to the
    target's DNS administrator. See OPSEC notes in the documentation.

    Examples:
        lookout enumerate example.com
        lookout enumerate example.com --wordlist custom.txt
        lookout enumerate example.com --output subs.json
        lookout enumerate example.com --no-crtsh
    """
    from osint.enumeration.dns_enum import enumerate_subdomains, load_wordlist

    # ---- OPSEC WARNING ----
    console.print()
    console.print(Panel(
        "[bold]This command is NOT fully passive.[/bold]\n"
        "\n"
        "DNS enumeration sends queries to DNS resolvers, which forward them\n"
        "to the target domain's authoritative nameservers.\n"
        "\n"
        "[bold yellow]What the target CAN see:[/bold yellow]\n"
        "  - Your DNS resolver's IP address (e.g. your ISP or 8.8.8.8)\n"
        "  - The subdomain names you are querying\n"
        "  - The timing and volume of queries\n"
        "\n"
        "[bold yellow]What the target CANNOT see:[/bold yellow]\n"
        "  - Your actual IP address (hidden behind the DNS resolver)\n"
        "\n"
        "[bold]Risk level:[/bold] LOW — but not zero.\n"
        "If the target monitors DNS logs (e.g. Cloudflare analytics), they\n"
        "may notice a burst of subdomain lookups from your resolver.\n"
        "\n"
        "[dim]The crt.sh lookup is fully passive (queries a public database).[/dim]",
        title="[bold yellow]OPSEC Warning — DNS Enumeration[/bold yellow]",
        border_style="yellow",
        padding=(1, 2),
    ))

    if not yes:
        if not typer.confirm("Do you want to continue?", default=True):
            console.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(0)

    console.print()

    # Validate domain
    try:
        indicator_type = detect_indicator_type(domain)
        if indicator_type != IndicatorType.DOMAIN:
            console.print(f"[red]Error:[/red] '{domain}' is not a domain (detected: {indicator_type.value})")
            raise typer.Exit(1)
    except DetectionError:
        console.print(f"[red]Error:[/red] '{domain}' is not a valid domain")
        raise typer.Exit(1)

    # Show wordlist info
    prefixes = load_wordlist(wordlist)
    console.print(f"[dim]Wordlist: {len(prefixes)} prefixes[/dim]")

    # Fetch crt.sh subdomains first if enabled
    crtsh_subs: Optional[list[str]] = None
    if with_crtsh:
        console.print("[dim]Fetching crt.sh certificate transparency data...[/dim]")
        try:
            async def fetch_crtsh() -> list[str]:
                from osint.clients.crtsh import CrtshClient
                from osint.core.config import get_settings
                settings = get_settings()
                async with CrtshClient(settings=settings) as client:
                    result = await client.lookup(domain, IndicatorType.DOMAIN)
                    if result and result.success and result.subdomains:
                        return result.subdomains
                    return []

            crtsh_subs = asyncio.run(fetch_crtsh())
            if crtsh_subs:
                console.print(f"[dim]crt.sh: found {len(crtsh_subs)} subdomains from certificates[/dim]")
        except Exception as e:
            console.print(f"[yellow]crt.sh failed ({e}), continuing with DNS only[/yellow]")
            crtsh_subs = None

    # Run enumeration with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(description="Enumerating subdomains...", total=None)

        try:
            enum_result = asyncio.run(enumerate_subdomains(
                domain=domain,
                wordlist_path=wordlist,
                concurrency=concurrency,
                timeout=timeout,
                crtsh_subdomains=crtsh_subs,
            ))
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

    # Display results
    console.print(f"\n[bold]Subdomain enumeration: {domain}[/bold]")
    console.print(
        f"[dim]Checked {enum_result.total_checked} subdomains in "
        f"{enum_result.duration_seconds:.1f}s[/dim]"
    )

    if not enum_result.resolved:
        console.print("\n[yellow]No subdomains found.[/yellow]")
        return

    console.print(f"\n[green]{enum_result.total_found} subdomains found:[/green]\n")

    # Results table
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Subdomain", style="cyan")
    table.add_column("IP(s)")
    table.add_column("Source", style="dim")

    # Group by IP to help spot shared hosting
    ip_counts: dict[str, int] = {}
    for sub in enum_result.resolved:
        for ip in sub.ips:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for sub in enum_result.resolved:
        ip_str = ", ".join(sub.ips)
        # Highlight if many subdomains point to the same IP
        shared = any(ip_counts.get(ip, 0) > 3 for ip in sub.ips)
        if shared:
            ip_display = Text(ip_str, style="yellow")
        else:
            ip_display = Text(ip_str)

        source_label = sub.source
        if sub.source == "both":
            source_label = "dns + crtsh"

        table.add_row(sub.subdomain, ip_display, source_label)

    console.print(table)

    # Show IP clustering
    shared_ips = {ip: count for ip, count in ip_counts.items() if count > 1}
    if shared_ips:
        console.print(f"\n[bold]IP clustering:[/bold]")
        for ip, count in sorted(shared_ips.items(), key=lambda x: x[1], reverse=True):
            console.print(f"  {ip} -> {count} subdomains", style="yellow" if count > 3 else "dim")

    # Tip
    if enum_result.resolved:
        top = enum_result.resolved[0]
        console.print(
            f"\n[dim]Tip: run [bold]lookout investigate {top.subdomain}[/bold] "
            f"to check a subdomain[/dim]"
        )

    # Save to file
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(enum_result.to_dict(), indent=2, default=str))
        console.print(f"\n[green]Results saved to {output}[/green]")


@app.command()
def dirscan(
    target: str = typer.Argument(
        ..., help="Target domain or URL (e.g. example.com or https://example.com/path)"
    ),
    wordlist: Optional[Path] = typer.Option(
        None,
        "--wordlist",
        "-w",
        help="Custom path wordlist (default: built-in phishing panel paths)",
    ),
    concurrency: int = typer.Option(
        20,
        "--concurrency",
        "-c",
        help="Max parallel HTTP requests",
    ),
    timeout: float = typer.Option(
        5.0,
        "--timeout",
        "-t",
        help="Timeout per request in seconds",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save results to file (JSON)",
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        "-p",
        help="Proxy URL (e.g. socks5://127.0.0.1:9050 or http://proxy:8080)",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the OPSEC warning confirmation",
    ),
) -> None:
    """
    Scan for exposed paths on a target (directory/path enumeration).

    WARNING: This command makes direct HTTP connections to the target.
    Your IP address WILL be visible in the target's server logs.
    Use --proxy to route traffic through a proxy (e.g. Tor, VPN proxy).

    Examples:
        lookout dirscan example.com
        lookout dirscan example.com --proxy socks5://127.0.0.1:9050
        lookout dirscan https://phishing-site.com/base
        lookout dirscan example.com --output paths.json
    """
    from osint.enumeration.path_enum import enumerate_paths, load_paths

    # ---- OPSEC WARNING ----
    console.print()
    if proxy:
        console.print(Panel(
            "[bold]This command makes direct HTTP requests to the target.[/bold]\n"
            "\n"
            f"[green]Proxy configured:[/green] {proxy}\n"
            "Your traffic will be routed through this proxy.\n"
            "\n"
            "[bold yellow]The target will see:[/bold yellow]\n"
            "  - The proxy's IP address (NOT yours)\n"
            "  - HTTP requests to each path in the wordlist\n"
            "  - The User-Agent string and request headers\n"
            "\n"
            "[bold green]The target will NOT see:[/bold green]\n"
            "  - Your real IP address\n"
            "\n"
            "[dim]Make sure your proxy is working before proceeding.[/dim]",
            title="[bold yellow]OPSEC Warning — Active Scanning (via proxy)[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        ))
    else:
        console.print(Panel(
            "[bold red]This command makes direct HTTP requests to the target.[/bold red]\n"
            "\n"
            "[bold red]YOUR IP ADDRESS WILL BE VISIBLE to the target.[/bold red]\n"
            "\n"
            "[bold yellow]What the target WILL see:[/bold yellow]\n"
            "  - Your public IP address in their server/access logs\n"
            "  - HTTP requests to every path in the wordlist\n"
            "  - The User-Agent string and request timing\n"
            "  - Potentially: alerts from WAF/anti-bot systems\n"
            "\n"
            "[bold]This is NOT passive reconnaissance.[/bold]\n"
            "This is active scanning. The target will know someone is\n"
            "probing their infrastructure.\n"
            "\n"
            "[bold cyan]To hide your IP, use a proxy:[/bold cyan]\n"
            "  lookout dirscan target.com --proxy socks5://127.0.0.1:9050\n"
            "  lookout dirscan target.com --proxy http://proxy:8080\n"
            "\n"
            "[dim]Supported proxy types: HTTP, HTTPS, SOCKS4, SOCKS5[/dim]",
            title="[bold red]OPSEC Warning — Active Scanning (NO PROXY)[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))

    if not yes:
        if not typer.confirm("Do you understand the risks and want to continue?", default=False):
            console.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(0)

    console.print()

    # Show wordlist info
    paths = load_paths(wordlist)
    console.print(f"[dim]Path wordlist: {len(paths)} paths[/dim]")

    # Determine schemes
    if proxy:
        console.print(f"[dim]Proxy: {proxy}[/dim]")
    if target.startswith(("http://", "https://")):
        console.print(f"[dim]Target: {target}[/dim]")
    else:
        console.print(f"[dim]Target: {target} (trying HTTPS and HTTP)[/dim]")

    # Run path enumeration
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Scanning paths...", total=None)

        try:
            scan_result = asyncio.run(enumerate_paths(
                target=target,
                wordlist_path=wordlist,
                concurrency=concurrency,
                timeout=timeout,
                proxy=proxy,
            ))
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)

    # Display results
    console.print(f"\n[bold]Path scan: {target}[/bold]")
    console.print(
        f"[dim]Checked {scan_result.total_checked} paths in "
        f"{scan_result.duration_seconds:.1f}s[/dim]"
    )

    if not scan_result.found:
        console.print("\n[green]No exposed paths found.[/green]")
        return

    console.print(f"\n[yellow]{scan_result.total_found} paths found:[/yellow]\n")

    # Results table grouped by category
    CATEGORY_STYLES = {
        "panel": ("bold red", "Admin/operator panel"),
        "login": ("red", "Login/authentication page"),
        "phishing-flow": ("red", "Phishing flow step"),
        "data-leak": ("bold yellow", "Exposed data/logs"),
        "webshell": ("bold red", "Webshell/backdoor"),
        "config": ("yellow", "Configuration file"),
        "telegram": ("yellow", "Telegram C2 integration"),
        "anti-bot": ("dim", "Anti-bot/detection evasion"),
        "wordpress": ("dim", "WordPress"),
        "other": ("dim", "Other"),
    }

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Status", justify="right", min_width=6)
    table.add_column("Path", style="cyan")
    table.add_column("Category")
    table.add_column("Size", justify="right")
    table.add_column("Details")

    for found in scan_result.found:
        # Status code coloring
        if 200 <= found.status_code < 300:
            status_style = "green"
        elif 300 <= found.status_code < 400:
            status_style = "yellow"
        elif found.status_code == 403:
            status_style = "red"
        else:
            status_style = "dim"

        status = Text(str(found.status_code), style=status_style)

        # Category
        cat_style, cat_label = CATEGORY_STYLES.get(
            found.category, ("dim", found.category)
        )
        category = Text(cat_label, style=cat_style)

        # Size
        if found.content_length > 0:
            if found.content_length > 1024 * 1024:
                size = f"{found.content_length / 1024 / 1024:.1f}M"
            elif found.content_length > 1024:
                size = f"{found.content_length / 1024:.1f}K"
            else:
                size = f"{found.content_length}B"
        else:
            size = "-"

        # Details
        details_parts = []
        if found.title:
            details_parts.append(f'"{found.title}"')
        if found.redirect_url:
            details_parts.append(f"-> {found.redirect_url}")
        if found.content_type and found.content_type != "text/html":
            details_parts.append(found.content_type)
        details = ", ".join(details_parts) if details_parts else "-"

        table.add_row(status, found.path, category, size, details)

    console.print(table)

    # Show catch-all filter summary when noise was suppressed
    if scan_result.filtered_count > 0 and scan_result.catch_all_pattern:
        console.print(
            f"[dim]Filtered {scan_result.filtered_count} paths with generic redirect "
            f"({scan_result.catch_all_pattern})[/dim]"
        )

    # Highlight critical findings
    critical_cats = {"panel", "webshell", "data-leak", "config"}
    critical = [f for f in scan_result.found
                if f.category in critical_cats and f.status_code == 200]
    if critical:
        console.print()
        console.print(Panel(
            "\n".join(
                f"[bold]{f.category.upper()}[/bold]: {f.url}"
                for f in critical
            ),
            title="[bold red]Critical findings[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))

    # Save to file
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(scan_result.to_dict(), indent=2, default=str))
        console.print(f"\n[green]Results saved to {output}[/green]")


# ---------------------------------------------------------------------------
# Cache commands
# ---------------------------------------------------------------------------

@cache_app.command("stats")
def cache_stats() -> None:
    """Show cache statistics."""
    cache = CacheManager()
    stats = cache.get_stats()
    cache.close()

    table = Table(title="Cache Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    for key, value in stats.items():
        if key == "by_source":
            for source, count in value.items():
                table.add_row(f"  {source}", str(count))
        else:
            table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)


@cache_app.command("clean")
def cache_clean() -> None:
    """Remove expired cache entries."""
    cache = CacheManager()
    count = cache.clean_expired()
    cache.close()
    console.print(f"[green]Removed {count} expired entries[/green]")


@cache_app.command("clear")
def cache_clear(
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Clear all cache entries."""
    if not confirm:
        confirm = typer.confirm("Are you sure you want to clear all cache entries?")
    if confirm:
        cache = CacheManager()
        count = cache.clear_all()
        cache.close()
        console.print(f"[green]Cleared {count} cache entries[/green]")
    else:
        console.print("[yellow]Cancelled[/yellow]")


# ---------------------------------------------------------------------------
# Config commands
# ---------------------------------------------------------------------------

@config_app.command("show")
def config_show() -> None:
    """Show current configuration, API tiers, and daily quota usage."""
    settings = get_settings()
    cache = CacheManager(settings)
    daily_usage = cache.get_all_daily_usage()
    cache.close()

    console.print(Panel("[bold]Lookout Configuration[/bold]"))

    # API Keys with tier and quota
    table = Table(title="API Status")
    table.add_column("API", style="cyan")
    table.add_column("Key")
    table.add_column("Tier")
    table.add_column("Enabled")
    table.add_column("Used today", justify="right")
    table.add_column("Daily quota", justify="right")

    apis = [
        "virustotal", "urlscan", "abuseipdb", "shodan",
        "whoisxml", "triage", "alienvault"
    ]
    for api in apis:
        has_key = settings.has_api_key(api)
        enabled = settings.is_api_enabled(api)
        tier = settings.get_api_tier(api)
        quota = settings.get_daily_quota(api)
        used = daily_usage.get(api, 0)

        tier_display = Text(
            tier,
            style="bold green" if tier == "premium" else "dim",
        )
        enabled_display = "[green]Yes[/green]" if enabled else "[red]No[/red]"

        # Quota display with color coding
        if quota <= 0:
            quota_str = "unlimited"
            used_style = "dim"
        elif used >= quota:
            quota_str = str(quota)
            used_style = "bold red"
        elif used >= quota * 0.9:
            quota_str = str(quota)
            used_style = "yellow"
        else:
            quota_str = str(quota)
            used_style = "green"

        table.add_row(
            api,
            "Yes" if has_key else "[red]No[/red]",
            tier_display,
            enabled_display,
            Text(str(used), style=used_style),
            quota_str,
        )

    # Free APIs
    free_apis = ["rdap", "crtsh", "threatfox", "urlhaus"]
    for api in free_apis:
        enabled = settings.is_api_enabled(api)
        used = daily_usage.get(api, 0)
        table.add_row(
            f"{api} (free)",
            "N/A",
            Text("free", style="dim"),
            "[green]Yes[/green]" if enabled else "[red]No[/red]",
            Text(str(used), style="dim"),
            "unlimited",
        )

    console.print(table)

    # Cache settings
    console.print(f"\n[bold]Cache:[/bold] {'Enabled' if settings.cache.enabled else 'Disabled'}")
    console.print(f"  Database: {settings.get_cache_path()}")
    console.print(f"  Default TTL: {settings.cache.default_ttl_hours} hours")

    # Tier info
    console.print(f"\n[dim]Tip: Set api_tiers in config/config.yaml to 'premium' "
                  f"to unlock higher rate limits and quotas.[/dim]")


@config_app.command("reload")
def config_reload() -> None:
    """Reload configuration from files."""
    reload_settings()
    console.print("[green]Configuration reloaded[/green]")


@app.command()
def version() -> None:
    """Show version information."""
    from osint import __version__

    console.print(f"Lookout v{__version__}")


if __name__ == "__main__":
    app()
