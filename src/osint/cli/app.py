"""Main CLI application using Typer."""

import asyncio
import json
import sys
from builtins import enumerate as _enumerate  # preserve builtin before Typer command shadows it
from datetime import datetime
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

from osint.analysis.email_analyzer import (
    HeaderAnalysis,
    analyze_eml_file,
    parse_email_address,
)
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
# Case management helpers
# ---------------------------------------------------------------------------

def _detect_case_dir() -> Optional[Path]:
    """Check if the current working directory (or a parent) contains a case.json file.

    Returns the path to the case directory if found, otherwise None.
    Looks in the current directory first, then one level up (to handle subdirectory runs).
    """
    cwd = Path.cwd()
    for candidate in (cwd, cwd.parent):
        if (candidate / "case.json").exists():
            return candidate
    return None


def _update_case_json(case_dir: Path, indicator: str) -> None:
    """Add an indicator to the indicators_investigated list in case.json.

    Args:
        case_dir: Path to the case directory containing case.json.
        indicator: The indicator value to record.
    """
    case_json_path = case_dir / "case.json"
    if not case_json_path.exists():
        return
    try:
        data = json.loads(case_json_path.read_text(encoding="utf-8"))
        investigated = data.get("indicators_investigated", [])
        if indicator not in investigated:
            investigated.append(indicator)
        data["indicators_investigated"] = investigated
        case_json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except (json.JSONDecodeError, OSError):
        pass  # Non-fatal — do not interrupt the command


def _auto_save_to_case(
    case_dir: Path,
    subdirectory: str,
    filename: str,
    content: str,
) -> Path:
    """Save content to a file inside a case subdirectory.

    Args:
        case_dir: Root case directory.
        subdirectory: Subdirectory within the case dir (e.g. 'reports' or 'data').
        filename: Target filename.
        content: Text content to write.

    Returns:
        The resolved output path.
    """
    target_dir = case_dir / subdirectory
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / filename
    target_path.write_text(content, encoding="utf-8")
    return target_path


# ---------------------------------------------------------------------------
# Next-steps tips
# ---------------------------------------------------------------------------

def _print_next_steps(command: str, context: dict) -> None:
    """Print contextual suggestions after a command finishes.

    Args:
        command: The name of the command that just ran ('investigate', 'enumerate',
                 'dirscan', 'detect', 'new').
        context: Dict with optional keys: 'value', 'indicator_type', 'domain',
                 'pivot_value', 'case_dir'.
    """
    console.print()
    console.print("[dim]Next steps:[/dim]")

    value = context.get("value", "<value>")
    indicator_type = context.get("indicator_type", "")
    case_dir = context.get("case_dir", "")

    if command == "detect":
        console.print(f"  [bold cyan]lookout investigate {value}[/bold cyan]         Run a full investigation")
        console.print(f"  [bold cyan]lookout investigate {value} --help[/bold cyan]  See all investigation options")

    elif command == "investigate":
        if indicator_type == "ip":
            domain = context.get("domain", "<domain>")
            console.print(f"  [bold cyan]lookout investigate {domain}[/bold cyan]        Investigate associated domains")
            console.print(f"  [bold cyan]lookout investigate {value} -o report.json[/bold cyan]   Save report")
        else:
            # domain / URL / hash
            pivot = context.get("pivot_value", "<pivot-value>")
            console.print(f"  [bold cyan]lookout enumerate {value}[/bold cyan]                  Find more subdomains")
            console.print(f"  [bold cyan]lookout dirscan {value}[/bold cyan]                    Scan for exposed paths/panels")
            console.print(f"  [bold cyan]lookout investigate {pivot}[/bold cyan]           Investigate a pivot indicator")
            console.print(
                f"  [bold cyan]lookout investigate {value} --format json --output report.json[/bold cyan]   Save report"
            )

    elif command == "enumerate":
        subdomain = context.get("subdomain", "<subdomain>")
        console.print(f"  [bold cyan]lookout investigate {subdomain}[/bold cyan]     Check a found subdomain")
        console.print(f"  [bold cyan]lookout dirscan {value}[/bold cyan]            Scan for exposed paths")

    elif command == "dirscan":
        console.print(f"  [bold cyan]lookout investigate {value}[/bold cyan]        Full investigation if not done yet")
        console.print(f"  [bold cyan]lookout enumerate {value}[/bold cyan]          Find more subdomains")

    elif command == "trace":
        final_domain = context.get("final_domain", "<final-domain>")
        console.print(f"  [bold cyan]lookout investigate {final_domain}[/bold cyan]    Full OSINT investigation on final destination")
        console.print(f"  [bold cyan]lookout dirscan {final_domain}[/bold cyan]        Scan for exposed paths/panels")
        console.print(f"  [bold cyan]lookout enumerate {final_domain}[/bold cyan]      Find subdomains of final destination")

    elif command == "new":
        case_name = context.get("case_name", value)
        console.print(f"  [bold cyan]cd {case_name}[/bold cyan]")
        console.print(f"  [bold cyan]lookout investigate <indicator>[/bold cyan]     Start investigating")
        console.print(f"  [bold cyan]lookout detect <value>[/bold cyan]              Check what type an indicator is")

    elif command == "email":
        domain = context.get("domain", "<domain>")
        console.print(f"  [bold cyan]lookout investigate {domain}[/bold cyan]        Investigate the sender domain")
        console.print(f"  [bold cyan]lookout headers <file.eml>[/bold cyan]          Analyse full email headers from an .eml file")
        console.print(f"  [bold cyan]lookout enumerate {domain}[/bold cyan]          Enumerate subdomains of the sender domain")

    elif command == "headers":
        domains = context.get("domains", [])
        ips = context.get("ips", [])
        if domains:
            first_domain = domains[0]
            console.print(f"  [bold cyan]lookout investigate {first_domain}[/bold cyan]   Investigate extracted domain")
        if ips:
            first_ip = ips[0]
            console.print(f"  [bold cyan]lookout investigate {first_ip}[/bold cyan]        Investigate origin IP")
        if not domains and not ips:
            console.print(f"  [bold cyan]lookout investigate <domain>[/bold cyan]           Investigate an extracted domain")
        console.print(f"  [bold cyan]lookout headers <file.eml> --investigate[/bold cyan]  Re-run with full OSINT enrichment")

    console.print()


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
    case: Optional[Path] = typer.Option(
        None,
        "--case",
        "-C",
        help="Case directory — auto-save report to <case-dir>/reports/ and update case.json",
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

    # Auto-detect case directory if --case not specified
    effective_case = case
    if effective_case is None:
        effective_case = _detect_case_dir()
        if effective_case is not None:
            console.print(f"[dim]Case directory detected: {effective_case}[/dim]")

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

    # Auto-save to case directory (all formats)
    if effective_case is not None:
        safe_value = value.replace("/", "_").replace(":", "_").replace("\\", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"investigate_{safe_value}_{timestamp}"

        report_gen = ReportGenerator()
        report = report_gen.create_report(result)

        # 1. Markdown report
        md_content = report_gen.to_markdown(report)
        pivots_md = _generate_pivot_markdown(result)
        if pivots_md:
            md_content += "\n" + pivots_md
        md_content = md_content.replace("*Generated by OSINT Tool*", "*Generated by Lookout*")
        _auto_save_to_case(effective_case, "reports", f"{base_name}.md", md_content)

        # 2. JSON (full data + assessment + pivots)
        json_data = result.to_dict()
        json_data["assessment"] = {
            "risk_summary": report.risk_summary,
            "key_findings": report.key_findings,
            "recommendations": report.recommendations,
        }
        json_data["pivot_indicators"] = [
            {"value": r.value, "type": r.indicator_type.value,
             "relationship": r.relationship, "source": r.source,
             "confidence": r.confidence}
            for r in report.related_indicators
        ]
        import json as _json
        _auto_save_to_case(
            effective_case, "reports", f"{base_name}.json",
            _json.dumps(json_data, indent=2, default=str),
        )

        # 3. Word (.docx) report
        try:
            docx_path = Path(effective_case) / "reports" / f"{base_name}.docx"
            docx_path.parent.mkdir(parents=True, exist_ok=True)
            report_gen.save_docx(report, docx_path)
        except Exception as e:
            console.print(f"[yellow]Could not generate .docx: {e}[/yellow]")

        console.print(
            f"[dim]Reports auto-saved to {Path(effective_case) / 'reports'}/ "
            f"(.md, .json, .docx)[/dim]"
        )
        _update_case_json(effective_case, value)

    # Next steps
    pivot_value = "<pivot-value>"
    # Try to extract the top pivot from results for a more useful tip
    try:
        from osint.models.results import CrtshResult, URLScanResult, ShodanResult
        for _src, _api_result in result.results.items():
            if _api_result and _api_result.success:
                if isinstance(_api_result, URLScanResult) and _api_result.page_ip:
                    pivot_value = _api_result.page_ip
                    break
                if isinstance(_api_result, CrtshResult) and _api_result.subdomains:
                    pivot_value = _api_result.subdomains[0]
                    break
    except Exception:
        pass

    _print_next_steps("investigate", {
        "value": value,
        "indicator_type": indicator_type.value,
        "pivot_value": pivot_value,
    })


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

    _print_next_steps("detect", {"value": value})


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
    case: Optional[Path] = typer.Option(
        None,
        "--case",
        "-C",
        help="Case directory — auto-save results to <case-dir>/data/ and update case.json",
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

    # Save to file
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(enum_result.to_dict(), indent=2, default=str))
        console.print(f"\n[green]Results saved to {output}[/green]")

    # Auto-detect case directory if --case not specified
    effective_case = case
    if effective_case is None:
        effective_case = _detect_case_dir()
        if effective_case is not None:
            console.print(f"[dim]Case directory detected: {effective_case}[/dim]")

    # Auto-save to case directory
    if effective_case is not None and enum_result.resolved:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"enumerate_{domain}_{timestamp}.json"
        content = json.dumps(enum_result.to_dict(), indent=2, default=str)
        saved_path = _auto_save_to_case(effective_case, "data", filename, content)
        console.print(f"[dim]Results auto-saved to {saved_path}[/dim]")
        _update_case_json(effective_case, domain)

    # Next steps
    first_sub = enum_result.resolved[0].subdomain if enum_result.resolved else "<subdomain>"
    _print_next_steps("enumerate", {"value": domain, "subdomain": first_sub})


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
    case: Optional[Path] = typer.Option(
        None,
        "--case",
        "-C",
        help="Case directory — auto-save results to <case-dir>/data/ and update case.json",
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

    # Auto-detect case directory if --case not specified
    effective_case = case
    if effective_case is None:
        effective_case = _detect_case_dir()
        if effective_case is not None:
            console.print(f"[dim]Case directory detected: {effective_case}[/dim]")

    # Auto-save to case directory
    if effective_case is not None and scan_result.found:
        safe_target = target.replace("/", "_").replace(":", "_").replace("\\", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dirscan_{safe_target}_{timestamp}.json"
        content = json.dumps(scan_result.to_dict(), indent=2, default=str)
        saved_path = _auto_save_to_case(effective_case, "data", filename, content)
        console.print(f"[dim]Results auto-saved to {saved_path}[/dim]")
        _update_case_json(effective_case, target)

    # Next steps
    _print_next_steps("dirscan", {"value": target})


# ---------------------------------------------------------------------------
# trace command
# ---------------------------------------------------------------------------

@app.command()
def trace(
    url: str = typer.Argument(
        ..., help="URL to trace (e.g. https://bit.ly/3xPhish)"
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy",
        "-p",
        help="Proxy URL (e.g. socks5://127.0.0.1:9050 or http://proxy:8080)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save trace result to file (JSON)",
    ),
    investigate_flag: bool = typer.Option(
        False,
        "--investigate",
        "-I",
        help="Auto-run lookout investigate on every unique domain found in the chain",
    ),
    case: Optional[Path] = typer.Option(
        None,
        "--case",
        "-C",
        help="Case directory — auto-save trace to <case-dir>/data/ and update case.json",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the OPSEC warning confirmation",
    ),
) -> None:
    """
    Follow a URL's redirect chain hop-by-hop and record each server.

    WARNING: This command makes direct HTTP connections to EVERY server
    in the redirect chain. Your IP will be visible to ALL of them.

    Examples:
        lookout trace https://bit.ly/3xPhish
        lookout trace https://short.url/abc --proxy socks5://127.0.0.1:9050
        lookout trace https://suspect.link --investigate
        lookout trace https://phish.link --output trace.json
    """
    from urllib.parse import urlparse as _urlparse

    from osint.enumeration.url_trace import trace_url

    # ---- OPSEC WARNING ----
    console.print()
    if proxy:
        console.print(Panel(
            "[bold]This command makes direct HTTP requests to each server in the redirect chain.[/bold]\n"
            "\n"
            f"[green]Proxy configured:[/green] {proxy}\n"
            "Your traffic will be routed through this proxy.\n"
            "\n"
            "[bold yellow]Every server in the chain will see:[/bold yellow]\n"
            "  - The proxy's IP address (NOT yours)\n"
            "  - A single GET request per hop\n"
            "  - The User-Agent string and request headers\n"
            "\n"
            "[bold green]They will NOT see:[/bold green]\n"
            "  - Your real IP address\n"
            "\n"
            "[dim]Redirect chains can span multiple different servers and CDNs.[/dim]",
            title="[bold yellow]OPSEC Warning — Active Redirect Tracing (via proxy)[/bold yellow]",
            border_style="yellow",
            padding=(1, 2),
        ))
    else:
        console.print(Panel(
            "[bold red]This command makes direct HTTP requests to the target.[/bold red]\n"
            "\n"
            "[bold red]YOUR IP ADDRESS WILL BE VISIBLE TO EVERY SERVER IN THE CHAIN.[/bold red]\n"
            "\n"
            "Redirect chains often pass through multiple servers:\n"
            "  URL shorteners, tracking redirectors, CDNs, and the final destination\n"
            "  — all of them will log your IP address.\n"
            "\n"
            "[bold yellow]What every server in the chain WILL see:[/bold yellow]\n"
            "  - Your public IP address in their access/server logs\n"
            "  - A GET request with your User-Agent\n"
            "  - The timestamp of your visit\n"
            "\n"
            "[bold]This is NOT passive reconnaissance.[/bold]\n"
            "You are making live HTTP connections to potentially hostile infrastructure.\n"
            "\n"
            "[bold cyan]To hide your IP, use a proxy:[/bold cyan]\n"
            "  lookout trace <url> --proxy socks5://127.0.0.1:9050\n"
            "  lookout trace <url> --proxy http://proxy:8080\n"
            "\n"
            "[dim]Supported proxy types: HTTP, HTTPS, SOCKS4, SOCKS5[/dim]",
            title="[bold red]OPSEC Warning — Active Redirect Tracing (NO PROXY)[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))

    if not yes:
        if not typer.confirm("Do you understand the risks and want to continue?", default=False):
            console.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(0)

    console.print()

    # Validate URL scheme
    parsed_input = _urlparse(url)
    if parsed_input.scheme not in ("http", "https"):
        console.print(
            f"[red]Error:[/red] URL must start with http:// or https://. Got: '{url}'"
        )
        raise typer.Exit(1)

    if proxy:
        console.print(f"[dim]Proxy: {proxy}[/dim]")
    console.print(f"[dim]Tracing: {url}[/dim]")

    # Run the trace
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Following redirect chain...", total=None)

        try:
            trace_result = asyncio.run(trace_url(
                url=url,
                max_redirects=20,
                timeout=10.0,
                proxy=proxy,
            ))
        except Exception as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1)

    # ---- Display results ----
    console.print(f"\n[bold]Redirect chain for:[/bold] {url}\n")

    if not trace_result.hops:
        console.print("[yellow]No hops recorded — the URL may be unreachable.[/yellow]")
        if trace_result.error:
            console.print(f"[red]Error:[/red] {trace_result.error}")
        raise typer.Exit(1)

    # Hops table
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("#", justify="right", style="dim", min_width=3)
    table.add_column("Status", justify="right", min_width=6)
    table.add_column("URL", style="cyan", max_width=60)
    table.add_column("Server")
    table.add_column("IP")

    for idx, hop in _enumerate(trace_result.hops, start=1):
        # Status coloring
        if hop.status_code == 0:
            status_text = Text("ERR", style="bold red")
        elif 200 <= hop.status_code < 300:
            status_text = Text(str(hop.status_code), style="green")
        elif 300 <= hop.status_code < 400:
            status_text = Text(str(hop.status_code), style="yellow")
        elif 400 <= hop.status_code < 500:
            status_text = Text(str(hop.status_code), style="red")
        else:
            status_text = Text(str(hop.status_code), style="bold red")

        # Truncate long URLs for display
        display_url = hop.url
        if len(display_url) > 60:
            display_url = display_url[:57] + "..."

        server_display = hop.server or "-"
        ip_display = hop.ip or "-"

        table.add_row(
            str(idx),
            status_text,
            display_url,
            server_display,
            ip_display,
        )

    console.print(table)

    # Final destination
    console.print()
    console.print(f"[bold]Final destination:[/bold] [cyan]{trace_result.final_url}[/cyan]")
    console.print(
        f"[dim]{trace_result.total_hops} hop(s) in {trace_result.duration_seconds:.2f}s[/dim]"
    )

    # Error notice
    if trace_result.error:
        console.print(f"\n[yellow]Note:[/yellow] {trace_result.error}")

    # Domains in chain summary
    if trace_result.domains_in_chain:
        console.print(f"\n[bold]Domains in chain ({len(trace_result.domains_in_chain)}):[/bold]")

        # Build a domain -> ip lookup from hops
        domain_to_ip: dict[str, str] = {}
        for hop in trace_result.hops:
            hop_parsed = _urlparse(hop.url)
            d = hop_parsed.hostname or ""
            if d and hop.ip:
                domain_to_ip[d] = hop.ip

        for domain in trace_result.domains_in_chain:
            ip_str = domain_to_ip.get(domain, "")
            if ip_str:
                console.print(f"  [cyan]{domain:<35}[/cyan] {ip_str}")
            else:
                console.print(f"  [cyan]{domain}[/cyan]")

    # Tip for final destination
    if trace_result.domains_in_chain:
        final_domain = trace_result.domains_in_chain[-1]
        console.print(
            f"\n[dim]Tip: run [bold cyan]lookout investigate {final_domain}[/bold cyan]"
            f" to check the final destination[/dim]"
        )

    # Save to explicit output file
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(trace_result.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"\n[green]Results saved to {output}[/green]")

    # Auto-detect case directory
    effective_case = case
    if effective_case is None:
        effective_case = _detect_case_dir()
        if effective_case is not None:
            console.print(f"[dim]Case directory detected: {effective_case}[/dim]")

    # Auto-save to case directory
    if effective_case is not None:
        safe_url = (
            url.replace("https://", "")
               .replace("http://", "")
               .replace("/", "_")
               .replace(":", "_")
               .replace("?", "_")
               .replace("&", "_")
               .replace("=", "_")
        )
        # Keep filename sane
        if len(safe_url) > 80:
            safe_url = safe_url[:80]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"trace_{safe_url}_{timestamp}.json"
        content = json.dumps(trace_result.to_dict(), indent=2, default=str)
        saved_path = _auto_save_to_case(effective_case, "data", filename, content)
        console.print(f"[dim]Trace auto-saved to {saved_path}[/dim]")
        _update_case_json(effective_case, url)

    # --investigate: run lookout investigate on each unique domain
    if investigate_flag and trace_result.domains_in_chain:
        console.print(f"\n[bold]Auto-investigating {len(trace_result.domains_in_chain)} domain(s)...[/bold]\n")
        console.print(Rule())
        for domain in trace_result.domains_in_chain:
            console.print(f"\n[bold cyan]>>> lookout investigate {domain}[/bold cyan]\n")
            try:
                investigate(
                    value=domain,
                    format=OutputFormat.TABLE,
                    output=None,
                    no_cache=False,
                    verbose=False,
                    case=effective_case,
                )
            except SystemExit:
                pass
            except Exception as exc:
                console.print(f"[yellow]Warning:[/yellow] investigate {domain} failed: {exc}")
        console.print(Rule())

    # Next steps
    final_domain_for_tips = (
        trace_result.domains_in_chain[-1]
        if trace_result.domains_in_chain
        else "<final-domain>"
    )
    _print_next_steps("trace", {"value": url, "final_domain": final_domain_for_tips})


# ---------------------------------------------------------------------------
# Email address investigation
# ---------------------------------------------------------------------------

@app.command()
def email(
    address: str = typer.Argument(..., help="Email address to analyse (e.g. security@phishing-bank.com)"),
    format: OutputFormat = typer.Option(
        OutputFormat.TABLE,
        "--format",
        "-f",
        help="Output format (table, json, markdown, docx)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save output to file",
    ),
    case: Optional[Path] = typer.Option(
        None,
        "--case",
        "-C",
        help="Case directory — auto-save results and update case.json",
    ),
) -> None:
    """
    Analyse an email address and investigate its domain.

    Parses the address, displays its components, then automatically runs a
    full OSINT investigation on the sender domain.  Passive only — no
    direct contact with the target infrastructure.

    Examples:
        lookout email security@phishing-bank.com
        lookout email noreply@suspicious.com --output result.json
        lookout email attacker@evil.com --case ./my-case
    """
    # Parse the address
    parsed = parse_email_address(address)
    if parsed is None:
        console.print(f"[red]Error:[/red] '{address}' does not look like a valid email address.")
        raise typer.Exit(1)

    # Auto-detect case directory
    effective_case = case
    if effective_case is None:
        effective_case = _detect_case_dir()
        if effective_case is not None:
            console.print(f"[dim]Case directory detected: {effective_case}[/dim]")

    # Display parsed info
    console.print()
    console.print(Rule("Email Address Analysis", style="bold cyan"))
    console.print()

    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Field", style="bold", min_width=14)
    info_table.add_column("Value", style="cyan")
    info_table.add_row("Email", parsed.full_address)
    info_table.add_row("Local part", parsed.local_part)
    info_table.add_row("Domain", parsed.domain)
    console.print(info_table)
    console.print()

    # Investigate the domain
    console.print(f"[dim]Investigating domain: {parsed.domain}[/dim]")

    async def run_investigation() -> InvestigationResult:
        async with Investigator() as investigator:
            return await investigator.investigate(parsed.domain, IndicatorType.DOMAIN)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description=f"Investigating {parsed.domain}...", total=None)
        try:
            result = asyncio.run(run_investigation())
        except OSINTError as e:
            console.print(f"[red]Error during investigation:[/red] {e}")
            raise typer.Exit(1)

    # Output
    if format == OutputFormat.JSON:
        output_json(result, output)
    elif format == OutputFormat.MARKDOWN:
        output_markdown(result, output)
    else:
        print_investigation_result(result)
        if output:
            output_json(result, output)

    # Auto-save to case
    if effective_case is not None:
        safe_addr = address.replace("@", "_at_").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"email_{safe_addr}_{timestamp}"

        report_gen = ReportGenerator()
        report = report_gen.create_report(result)

        md_content = report_gen.to_markdown(report)
        pivots_md = _generate_pivot_markdown(result)
        if pivots_md:
            md_content += "\n" + pivots_md
        md_content = md_content.replace("*Generated by OSINT Tool*", "*Generated by Lookout*")
        _auto_save_to_case(effective_case, "reports", f"{base_name}.md", md_content)

        import json as _json
        json_data = result.to_dict()
        json_data["email_address"] = parsed.to_dict()
        _auto_save_to_case(
            effective_case, "reports", f"{base_name}.json",
            _json.dumps(json_data, indent=2, default=str),
        )

        console.print(f"[dim]Reports auto-saved to {Path(effective_case) / 'reports'}/[/dim]")
        _update_case_json(effective_case, address)
        _update_case_json(effective_case, parsed.domain)

    _print_next_steps("email", {"value": address, "domain": parsed.domain})


# ---------------------------------------------------------------------------
# Email header analysis
# ---------------------------------------------------------------------------

@app.command()
def headers(
    file: Path = typer.Argument(..., help="Path to .eml file or plain-text header dump"),
    investigate: bool = typer.Option(
        False,
        "--investigate",
        "-I",
        help="Auto-investigate all extracted domains and the origin IP",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Save header analysis to JSON",
    ),
    case: Optional[Path] = typer.Option(
        None,
        "--case",
        "-C",
        help="Case directory — auto-save results and update case.json",
    ),
) -> None:
    """
    Parse and analyse email headers from an .eml file or plain-text header dump.

    Extracts sender information, the full routing chain, SPF/DKIM/DMARC
    results, and derived threat indicators.  Optionally runs OSINT
    investigations on every extracted domain and the origin IP.

    Passive command — parses local files and optionally calls APIs.

    Examples:
        lookout headers phishing.eml
        lookout headers headers.txt --investigate
        lookout headers phishing.eml --output analysis.json --case ./my-case
    """
    # Parse the file
    if not file.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(1)

    try:
        analysis = analyze_eml_file(file)
    except (OSError, ValueError) as e:
        console.print(f"[red]Error reading file:[/red] {e}")
        raise typer.Exit(1)

    # Auto-detect case directory
    effective_case = case
    if effective_case is None:
        effective_case = _detect_case_dir()
        if effective_case is not None:
            console.print(f"[dim]Case directory detected: {effective_case}[/dim]")

    # ------------------------------------------------------------------
    # Display: sender information
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule("Email Header Analysis", style="bold cyan"))
    console.print()

    console.print("[bold]Sender Information:[/bold]")
    sender_table = Table(show_header=False, box=None, padding=(0, 2))
    sender_table.add_column("Field", style="bold", min_width=14)
    sender_table.add_column("Value")

    def _fmt_addr(addr_info) -> str:
        if addr_info is None:
            return "[dim]not present[/dim]"
        return f"[cyan]{addr_info.full_address}[/cyan]"

    sender_table.add_row("From", _fmt_addr(analysis.from_address))
    sender_table.add_row("Return-Path", _fmt_addr(analysis.return_path))
    sender_table.add_row("Reply-To", _fmt_addr(analysis.reply_to))
    if analysis.subject:
        sender_table.add_row("Subject", analysis.subject)
    if analysis.date:
        sender_table.add_row("Date", analysis.date)
    if analysis.message_id:
        sender_table.add_row("Message-ID", analysis.message_id)
    console.print(sender_table)

    # ------------------------------------------------------------------
    # Display: authentication
    # ------------------------------------------------------------------
    console.print()
    console.print("[bold]Authentication:[/bold]")

    auth = analysis.auth_results
    auth_table = Table(show_header=False, box=None, padding=(0, 2))
    auth_table.add_column("Mechanism", style="bold", min_width=6)
    auth_table.add_column("Result")
    auth_table.add_column("Detail", style="dim")

    def _auth_style(result: str) -> str:
        r = result.lower()
        if r == "pass":
            return "green"
        if r in ("fail", "permerror"):
            return "bold red"
        if r in ("softfail", "temperror"):
            return "yellow"
        if r == "not checked":
            return "dim"
        return "white"

    for mechanism, result, detail in (
        ("SPF", auth.spf, auth.spf_detail),
        ("DKIM", auth.dkim, auth.dkim_detail),
        ("DMARC", auth.dmarc, auth.dmarc_detail),
    ):
        style = _auth_style(result)
        auth_table.add_row(mechanism, Text(result.upper(), style=style), detail[:80] if detail else "")
    console.print(auth_table)

    # ------------------------------------------------------------------
    # Display: sending chain
    # ------------------------------------------------------------------
    if analysis.received_chain:
        console.print()
        console.print("[bold]Sending Chain[/bold] [dim](newest first)[/dim]")
        chain_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        chain_table.add_column("#", justify="right", min_width=3)
        chain_table.add_column("From", min_width=20)
        chain_table.add_column("IP", min_width=16, style="cyan")
        chain_table.add_column("By", min_width=20)
        chain_table.add_column("Timestamp")

        for idx, hop in _enumerate(analysis.received_chain, start=1):
            from_str = hop.from_host or "[dim]-[/dim]"
            ip_str = hop.from_ip or "[dim]-[/dim]"
            by_str = hop.by_host or "[dim]-[/dim]"
            ts_str = hop.timestamp or "[dim]-[/dim]"
            chain_table.add_row(str(idx), from_str, ip_str, by_str, ts_str)
        console.print(chain_table)

    # ------------------------------------------------------------------
    # Display: findings
    # ------------------------------------------------------------------
    if analysis.findings:
        console.print()
        console.print("[bold]Findings:[/bold]")
        for finding in analysis.findings:
            console.print(f"  [yellow]![/yellow] {finding}")

    # ------------------------------------------------------------------
    # Display: extracted indicators
    # ------------------------------------------------------------------
    if analysis.domains or analysis.ips:
        console.print()
        console.print("[bold]Extracted Indicators:[/bold]")
        ioc_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        ioc_table.add_column("Type", min_width=8)
        ioc_table.add_column("Value", style="cyan")
        ioc_table.add_column("Source", style="dim")

        # Map domains to their source for display
        domain_sources: dict[str, str] = {}
        if analysis.from_address:
            domain_sources[analysis.from_address.domain] = "From header"
        if analysis.return_path:
            domain_sources[analysis.return_path.domain] = "Return-Path"
        if analysis.reply_to:
            domain_sources[analysis.reply_to.domain] = "Reply-To"

        for domain in analysis.domains:
            source = domain_sources.get(domain, "Received headers")
            ioc_table.add_row("DOMAIN", domain, source)
        for ip in analysis.ips:
            ioc_table.add_row("IP", ip, "Received header")
        console.print(ioc_table)

    # ------------------------------------------------------------------
    # Save JSON output
    # ------------------------------------------------------------------
    import json as _json

    analysis_json = _json.dumps(analysis.to_dict(), indent=2, default=str)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(analysis_json, encoding="utf-8")
        console.print(f"\n[green]Analysis saved to {output}[/green]")

    # Auto-save to case
    if effective_case is not None:
        safe_name = file.stem.replace(" ", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"headers_{safe_name}_{timestamp}.json"
        saved_path = _auto_save_to_case(effective_case, "data", filename, analysis_json)
        console.print(f"[dim]Analysis auto-saved to {saved_path}[/dim]")

        # Record all extracted indicators in case.json
        for domain in analysis.domains:
            _update_case_json(effective_case, domain)
        for ip in analysis.ips:
            _update_case_json(effective_case, ip)
        if analysis.from_address:
            _update_case_json(effective_case, analysis.from_address.full_address)

    # ------------------------------------------------------------------
    # Optional: investigate all indicators
    # ------------------------------------------------------------------
    if investigate and (analysis.domains or analysis.ips):
        indicators_to_investigate: list[tuple[str, IndicatorType]] = []
        for domain in analysis.domains:
            indicators_to_investigate.append((domain, IndicatorType.DOMAIN))
        # Only investigate the last (origin) IP from the Received chain
        if analysis.ips:
            origin_ip = analysis.ips[-1]
            try:
                ip_type = detect_indicator_type(origin_ip)
                indicators_to_investigate.append((origin_ip, ip_type))
            except DetectionError:
                pass

        console.print()
        console.print(Rule(f"Investigating {len(indicators_to_investigate)} indicators", style="bold cyan"))

        async def run_all_investigations() -> list:
            async with Investigator() as investigator:
                tasks = [
                    investigator.investigate(val, itype)
                    for val, itype in indicators_to_investigate
                ]
                return await asyncio.gather(*tasks, return_exceptions=True)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(
                description=f"Investigating {len(indicators_to_investigate)} indicators...",
                total=None,
            )
            try:
                inv_results = asyncio.run(run_all_investigations())
            except Exception as e:
                console.print(f"[red]Error during investigation:[/red] {e}")
                raise typer.Exit(1)

        for (val, _itype), inv_result in zip(indicators_to_investigate, inv_results):
            if isinstance(inv_result, Exception):
                console.print(f"[red]Failed to investigate {val}:[/red] {inv_result}")
                continue
            console.print()
            print_investigation_result(inv_result)

            # Auto-save each investigation result to case
            if effective_case is not None:
                safe_val = val.replace("/", "_").replace(":", "_").replace("\\", "_")
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                base_name = f"investigate_{safe_val}_{ts}"

                try:
                    report_gen = ReportGenerator()
                    report = report_gen.create_report(inv_result)
                    md_content = report_gen.to_markdown(report)
                    pivots_md = _generate_pivot_markdown(inv_result)
                    if pivots_md:
                        md_content += "\n" + pivots_md
                    md_content = md_content.replace("*Generated by OSINT Tool*", "*Generated by Lookout*")
                    _auto_save_to_case(effective_case, "reports", f"{base_name}.md", md_content)
                    json_data = inv_result.to_dict()
                    _auto_save_to_case(
                        effective_case, "reports", f"{base_name}.json",
                        _json.dumps(json_data, indent=2, default=str),
                    )
                except Exception as save_err:
                    console.print(f"[yellow]Could not auto-save report for {val}: {save_err}[/yellow]")

    _print_next_steps("headers", {
        "value": str(file),
        "domains": analysis.domains,
        "ips": analysis.ips,
    })


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
def new(
    name: str = typer.Argument(..., help="Case name (used as directory name, e.g. phishing-example-com)"),
    description: str = typer.Option(
        "",
        "--description",
        "-d",
        help="Optional short description of the case",
    ),
) -> None:
    """
    Create a new case directory structure.

    Creates a case directory with standard subdirectories and a case.json
    metadata file. Run this before starting an investigation to keep all
    artifacts organized in one place.

    Examples:
        lookout new phishing-example-com
        lookout new phishing-example-com -d "Phishing kit targeting example.com customers"
    """
    case_dir = Path.cwd() / name

    if case_dir.exists():
        console.print(f"[red]Error:[/red] Directory '{name}' already exists.")
        raise typer.Exit(1)

    # Create directory structure
    subdirs = ["reports", "data", "evidence"]
    try:
        case_dir.mkdir(parents=True)
        for subdir in subdirs:
            (case_dir / subdir).mkdir()
    except OSError as e:
        console.print(f"[red]Error creating directory structure:[/red] {e}")
        raise typer.Exit(1)

    # Write .gitignore to prevent case data from being committed
    (case_dir / ".gitignore").write_text(
        "# This is a Lookout case directory.\n"
        "# Case data should NEVER be committed to a git repository.\n"
        "*\n",
        encoding="utf-8",
    )

    # Write case.json
    case_metadata = {
        "name": name,
        "created": datetime.now().isoformat(timespec="seconds"),
        "description": description,
        "indicators_investigated": [],
        "status": "open",
    }
    try:
        (case_dir / "case.json").write_text(
            json.dumps(case_metadata, indent=2),
            encoding="utf-8",
        )
    except OSError as e:
        console.print(f"[red]Error writing case.json:[/red] {e}")
        raise typer.Exit(1)

    # Confirm creation
    console.print(f"\n[green]Case directory created:[/green] {case_dir}")
    console.print()

    tree_table = Table(show_header=False, box=None, padding=(0, 1))
    tree_table.add_column("", style="cyan")
    tree_table.add_column("", style="dim")
    tree_table.add_row(f"{name}/", "")
    tree_table.add_row("  reports/", "Investigation reports (md, json, docx)")
    tree_table.add_row("  data/", "Enumeration results, raw data")
    tree_table.add_row("  evidence/", "Screenshots, samples, exports")
    tree_table.add_row("  case.json", "Case metadata and investigated indicators")
    console.print(tree_table)

    if description:
        console.print(f"\n[dim]Description:[/dim] {description}")

    _print_next_steps("new", {"case_name": name})


@app.command()
def version() -> None:
    """Show version information."""
    from osint import __version__

    console.print(f"Lookout v{__version__}")


if __name__ == "__main__":
    app()
