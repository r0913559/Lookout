"""API result models."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from osint.core.constants import APISource, IndicatorType, RiskLevel


class APIResult(BaseModel):
    """Base class for API results."""

    source: APISource
    indicator_type: IndicatorType
    indicator_value: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    success: bool = True
    error_message: Optional[str] = None
    raw_data: Optional[dict[str, Any]] = None
    cached: bool = False

    # Risk assessment
    risk_score: Optional[float] = None  # 0-100
    risk_level: RiskLevel = RiskLevel.UNKNOWN

    def calculate_risk_level(self) -> RiskLevel:
        """Calculate risk level from score."""
        if self.risk_score is not None:
            self.risk_level = RiskLevel.from_score(self.risk_score)
        return self.risk_level


class VirusTotalResult(APIResult):
    """VirusTotal API result."""

    source: APISource = APISource.VIRUSTOTAL

    # Detection stats
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_scanners: int = 0

    # Metadata
    last_analysis_date: Optional[datetime] = None
    reputation: Optional[int] = None
    categories: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    # Domain/IP specific
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    whois: Optional[str] = None
    asn: Optional[int] = None
    as_owner: Optional[str] = None
    country: Optional[str] = None

    # Hash specific
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    magic: Optional[str] = None
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    md5: Optional[str] = None

    def calculate_risk_score(self) -> float:
        """Calculate risk score based on VT detections."""
        if self.total_scanners == 0:
            return 0.0

        # Weight malicious more heavily than suspicious
        weighted_detections = self.malicious + (self.suspicious * 0.5)
        ratio = weighted_detections / self.total_scanners

        # Scale to 0-100
        self.risk_score = min(ratio * 150, 100)  # Cap at 100
        self.calculate_risk_level()
        return self.risk_score


class URLScanResult(APIResult):
    """URLScan.io API result."""

    source: APISource = APISource.URLSCAN

    # Scan info
    scan_id: Optional[str] = None
    scan_url: Optional[str] = None
    screenshot_url: Optional[str] = None
    result_url: Optional[str] = None

    # Page info
    page_title: Optional[str] = None
    page_ip: Optional[str] = None
    page_country: Optional[str] = None
    page_server: Optional[str] = None
    page_asn: Optional[str] = None

    # Verdicts
    malicious: bool = False
    score: int = 0
    categories: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)

    # Technical
    links: list[str] = Field(default_factory=list)
    certificates: list[dict[str, Any]] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)


class AbuseIPDBResult(APIResult):
    """AbuseIPDB API result."""

    source: APISource = APISource.ABUSEIPDB

    # Core data
    ip_address: Optional[str] = None
    is_public: bool = True
    ip_version: int = 4
    is_whitelisted: bool = False

    # Abuse metrics
    abuse_confidence_score: int = 0  # 0-100
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: Optional[datetime] = None

    # Network info
    isp: Optional[str] = None
    domain: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    usage_type: Optional[str] = None

    # Reports
    reports: list[dict[str, Any]] = Field(default_factory=list)

    def calculate_risk_score(self) -> float:
        """Use AbuseIPDB's confidence score as risk score."""
        self.risk_score = float(self.abuse_confidence_score)
        self.calculate_risk_level()
        return self.risk_score


class ShodanResult(APIResult):
    """Shodan API result."""

    source: APISource = APISource.SHODAN

    # Host info
    ip_str: Optional[str] = None
    hostnames: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None

    # Services
    ports: list[int] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)

    # Vulnerabilities
    vulns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    # OS detection
    os: Optional[str] = None
    last_update: Optional[datetime] = None


class RDAPResult(APIResult):
    """RDAP/WHOIS result (no auth required)."""

    source: APISource = APISource.RDAP

    # Registration info
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    registrar_url: Optional[str] = None
    creation_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None

    # Status
    status: list[str] = Field(default_factory=list)

    # Nameservers
    nameservers: list[str] = Field(default_factory=list)

    # Contact (often redacted)
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None

    # IP-specific
    network_name: Optional[str] = None
    network_handle: Optional[str] = None
    network_cidr: Optional[str] = None


class CrtshResult(APIResult):
    """Certificate Transparency (crt.sh) result."""

    source: APISource = APISource.CRTSH

    # Certificates found
    certificates: list[dict[str, Any]] = Field(default_factory=list)
    total_certificates: int = 0

    # Extracted domains
    subdomains: list[str] = Field(default_factory=list)


class ThreatFoxResult(APIResult):
    """ThreatFox (abuse.ch) result."""

    source: APISource = APISource.THREATFOX

    # IOC matches
    ioc_matches: list[dict[str, Any]] = Field(default_factory=list)
    total_matches: int = 0

    # Threat info
    threat_types: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    confidence_levels: list[int] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def calculate_risk_score(self) -> float:
        """Calculate risk based on ThreatFox matches."""
        if self.total_matches == 0:
            self.risk_score = 0.0
        else:
            # Any match is concerning
            avg_confidence = (
                sum(self.confidence_levels) / len(self.confidence_levels)
                if self.confidence_levels
                else 50
            )
            self.risk_score = min(50 + avg_confidence * 0.5, 100)
        self.calculate_risk_level()
        return self.risk_score


class URLhausResult(APIResult):
    """URLhaus (abuse.ch) result."""

    source: APISource = APISource.URLHAUS

    # URL info
    url_status: Optional[str] = None  # online, offline, unknown
    threat: Optional[str] = None  # malware_download, etc.
    url_id: Optional[str] = None
    host: Optional[str] = None

    # Threat info
    tags: list[str] = Field(default_factory=list)
    payloads: list[dict[str, Any]] = Field(default_factory=list)
    blacklists: dict[str, str] = Field(default_factory=dict)

    # Timeline
    date_added: Optional[datetime] = None
    last_online: Optional[datetime] = None

    def calculate_risk_score(self) -> float:
        """Calculate risk based on URLhaus data."""
        if self.url_status is None:
            self.risk_score = 0.0
        elif self.url_status == "online" and self.threat:
            self.risk_score = 90.0  # Active threat
        elif self.threat:
            self.risk_score = 70.0  # Known threat, status unknown
        else:
            self.risk_score = 30.0  # Listed but no specific threat
        self.calculate_risk_level()
        return self.risk_score


class WhoisXMLResult(APIResult):
    """WhoisXML API result."""

    source: APISource = APISource.WHOISXML

    # Domain info
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None

    # Registrant
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_email: Optional[str] = None

    # Nameservers
    nameservers: list[str] = Field(default_factory=list)

    # DNS history
    dns_records: list[dict[str, Any]] = Field(default_factory=list)


class TriageResult(APIResult):
    """Hatching Triage sandbox result."""

    source: APISource = APISource.TRIAGE

    # Sample info
    sample_id: Optional[str] = None
    sample_sha256: Optional[str] = None
    target: Optional[str] = None

    # Analysis
    score: int = 0  # 0-10
    family: Optional[str] = None
    tags: list[str] = Field(default_factory=list)

    # Behavioral
    processes: list[dict[str, Any]] = Field(default_factory=list)
    network: list[dict[str, Any]] = Field(default_factory=list)
    signatures: list[str] = Field(default_factory=list)

    # Reports
    report_url: Optional[str] = None


class AlienVaultResult(APIResult):
    """AlienVault OTX result."""

    source: APISource = APISource.ALIENVAULT

    # Pulse info
    pulse_count: int = 0
    pulses: list[dict[str, Any]] = Field(default_factory=list)

    # General info
    reputation: Optional[int] = None
    country_code: Optional[str] = None
    asn: Optional[str] = None

    # Related IOCs
    related_domains: list[str] = Field(default_factory=list)
    related_ips: list[str] = Field(default_factory=list)
    related_hashes: list[str] = Field(default_factory=list)
    related_urls: list[str] = Field(default_factory=list)
