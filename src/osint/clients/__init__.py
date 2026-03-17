"""API clients for threat intelligence sources."""

from osint.clients.base import BaseAPIClient
from osint.clients.virustotal import VirusTotalClient
from osint.clients.urlscan import URLScanClient
from osint.clients.abuseipdb import AbuseIPDBClient
from osint.clients.shodan import ShodanClient
from osint.clients.alienvault import AlienVaultClient
from osint.clients.rdap import RDAPClient
from osint.clients.crtsh import CrtshClient
from osint.clients.threatfox import ThreatFoxClient
from osint.clients.urlhaus import URLhausClient

__all__ = [
    "BaseAPIClient",
    # Premium (require API key)
    "VirusTotalClient",
    "URLScanClient",
    "AbuseIPDBClient",
    "ShodanClient",
    "AlienVaultClient",
    # Free (no API key)
    "RDAPClient",
    "CrtshClient",
    "ThreatFoxClient",
    "URLhausClient",
]
