"""Email header parser and email address analyzer.

Parses raw email headers (from .eml files or pasted header text) and
extracts sender information, routing chain, authentication results,
and derived threat indicators.

No external dependencies — uses the Python standard library only.
"""

from __future__ import annotations

import email
import email.parser
import email.policy
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EmailAddressInfo:
    """Parsed email address information."""

    full_address: str
    local_part: str
    domain: str

    def to_dict(self) -> dict:
        return {
            "full_address": self.full_address,
            "local_part": self.local_part,
            "domain": self.domain,
        }


@dataclass
class ReceivedHop:
    """A single hop in the Received header chain."""

    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    by_ip: Optional[str] = None
    timestamp: Optional[str] = None
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "from_host": self.from_host,
            "from_ip": self.from_ip,
            "by_host": self.by_host,
            "by_ip": self.by_ip,
            "timestamp": self.timestamp,
            "raw": self.raw,
        }


@dataclass
class AuthenticationResults:
    """SPF/DKIM/DMARC results."""

    # Possible values: pass, fail, softfail, neutral, permerror, temperror, none, not checked
    spf: str = "not checked"
    dkim: str = "not checked"
    dmarc: str = "not checked"
    spf_detail: str = ""
    dkim_detail: str = ""
    dmarc_detail: str = ""

    def to_dict(self) -> dict:
        return {
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "spf_detail": self.spf_detail,
            "dkim_detail": self.dkim_detail,
            "dmarc_detail": self.dmarc_detail,
        }


@dataclass
class HeaderAnalysis:
    """Full email header analysis result."""

    # Addresses
    from_address: Optional[EmailAddressInfo] = None
    return_path: Optional[EmailAddressInfo] = None
    reply_to: Optional[EmailAddressInfo] = None
    to_addresses: list[EmailAddressInfo] = field(default_factory=list)

    # Subject / metadata
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None

    # Routing
    received_chain: list[ReceivedHop] = field(default_factory=list)

    # Authentication
    auth_results: AuthenticationResults = field(default_factory=AuthenticationResults)

    # Extracted indicators
    domains: list[str] = field(default_factory=list)   # unique domains from all headers
    ips: list[str] = field(default_factory=list)        # unique IPs from Received headers
    urls: list[str] = field(default_factory=list)       # URLs found in headers

    # Warnings / findings
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "from_address": self.from_address.to_dict() if self.from_address else None,
            "return_path": self.return_path.to_dict() if self.return_path else None,
            "reply_to": self.reply_to.to_dict() if self.reply_to else None,
            "to_addresses": [a.to_dict() for a in self.to_addresses],
            "subject": self.subject,
            "date": self.date,
            "message_id": self.message_id,
            "received_chain": [h.to_dict() for h in self.received_chain],
            "auth_results": self.auth_results.to_dict(),
            "domains": self.domains,
            "ips": self.ips,
            "urls": self.urls,
            "findings": self.findings,
        }


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# IPv4 address (strict: avoids partial matches inside longer strings)
_RE_IPV4 = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# IPv6 address (covers full, compressed, and mixed forms)
_RE_IPV6 = re.compile(
    r"\[?"
    r"("
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"         # full
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                       # trailing ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"      # n:...:n
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"     # leading ::
    r"|::1"                                                 # loopback
    r")"
    r"\]?"
)

# Hostname in a Received header (alphanumeric + dots + hyphens)
_RE_HOSTNAME = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+)\b")

# URLs in header values
_RE_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# SPF/DKIM/DMARC result keywords
_AUTH_RESULTS = ("pass", "fail", "softfail", "neutral", "none", "permerror", "temperror")


# ---------------------------------------------------------------------------
# Email address parsing
# ---------------------------------------------------------------------------

def parse_email_address(addr: str) -> Optional[EmailAddressInfo]:
    """Parse an email address string into its components.

    Handles formats:
    - ``"Display Name" <user@domain.com>``
    - ``<user@domain.com>``
    - ``user@domain.com``

    Args:
        addr: Raw address string, possibly including display name.

    Returns:
        EmailAddressInfo or None if parsing fails.
    """
    if not addr:
        return None

    addr = addr.strip()

    # Extract the angle-bracket portion if present
    angle_match = re.search(r"<([^>]+)>", addr)
    if angle_match:
        raw_email = angle_match.group(1).strip()
    else:
        raw_email = addr.strip()

    # Remove any display name that was before the bare address
    # e.g. "Foo Bar user@domain.com" — take the last token that looks like an email
    if " " in raw_email:
        # Pick the part that contains @
        parts = raw_email.split()
        candidates = [p for p in parts if "@" in p]
        if candidates:
            raw_email = candidates[-1]
        else:
            return None

    if "@" not in raw_email:
        return None

    # Normalise and split
    raw_email = raw_email.lower()
    at_index = raw_email.rfind("@")
    local_part = raw_email[:at_index]
    domain = raw_email[at_index + 1:]

    if not local_part or not domain or "." not in domain:
        return None

    return EmailAddressInfo(
        full_address=raw_email,
        local_part=local_part,
        domain=domain,
    )


# ---------------------------------------------------------------------------
# Received header parsing
# ---------------------------------------------------------------------------

def _extract_ip_from_segment(text: str) -> Optional[str]:
    """Return the first IP (v4 or v6) found inside a parenthesised segment."""
    # IPv4 first — more common and unambiguous
    m = _RE_IPV4.search(text)
    if m:
        return m.group(0)
    # IPv6
    m = _RE_IPV6.search(text)
    if m:
        return m.group(1)
    return None


def _extract_hostname_from_segment(text: str) -> Optional[str]:
    """Return the first plausible hostname from a Received header segment."""
    # Prefer the token immediately after 'from' or 'by' (before any parenthesis)
    stripped = text.split("(")[0].strip()
    m = _RE_HOSTNAME.search(stripped)
    if m:
        return m.group(1)
    return None


def parse_received_header(raw: str) -> ReceivedHop:
    """Parse a single Received: header value into a ReceivedHop.

    The canonical Received header format is::

        from <host> (<ip>) by <host> (<ip>); <timestamp>

    Many MTAs deviate from this — we try to be resilient.

    Args:
        raw: The header value (the part after ``Received:``).

    Returns:
        ReceivedHop with whatever fields could be extracted.
    """
    hop = ReceivedHop(raw=raw.strip())

    # Split into content and timestamp (timestamp is after the semicolon)
    parts = raw.split(";", 1)
    if len(parts) == 2:
        hop.timestamp = parts[1].strip()
    content = parts[0]

    # --- 'from' segment ---
    from_match = re.search(r"\bfrom\s+(.+?)(?:\s+by\s+|\s+via\s+|\s+with\s+|$)", content, re.IGNORECASE | re.DOTALL)
    if from_match:
        from_segment = from_match.group(1)
        hop.from_host = _extract_hostname_from_segment(from_segment)
        hop.from_ip = _extract_ip_from_segment(from_segment)

    # --- 'by' segment ---
    by_match = re.search(r"\bby\s+(.+?)(?:\s+via\s+|\s+with\s+|\s+id\s+|\s+for\s+|;|$)", content, re.IGNORECASE | re.DOTALL)
    if by_match:
        by_segment = by_match.group(1)
        hop.by_host = _extract_hostname_from_segment(by_segment)
        hop.by_ip = _extract_ip_from_segment(by_segment)

    return hop


# ---------------------------------------------------------------------------
# Authentication-Results parsing
# ---------------------------------------------------------------------------

def _extract_auth_result(text: str, mechanism: str) -> tuple[str, str]:
    """Extract a pass/fail/etc result for an auth mechanism from a header value.

    Args:
        text: The full Authentication-Results header value.
        mechanism: One of 'spf', 'dkim', or 'dmarc'.

    Returns:
        Tuple of (result_keyword, detail_string).
    """
    # Pattern: mechanism=<result> (optional detail after whitespace or semicolon)
    pattern = re.compile(
        rf"\b{mechanism}\s*=\s*(\S+)",
        re.IGNORECASE,
    )
    m = pattern.search(text)
    if not m:
        return "none", ""

    result_raw = m.group(1).rstrip(";,")
    result_lower = result_raw.lower()

    # Normalise to known keywords
    result = result_lower if result_lower in _AUTH_RESULTS else result_lower

    # Extract detail (the rest of the clause until the next semicolon or end)
    start = m.end()
    rest = text[start:]
    semi_pos = rest.find(";")
    detail_fragment = rest[:semi_pos].strip() if semi_pos != -1 else rest.strip()
    # Truncate excessively long detail strings
    detail = detail_fragment[:200] if detail_fragment else ""

    return result, detail


def parse_authentication_results(headers: dict) -> AuthenticationResults:
    """Parse SPF/DKIM/DMARC status from email headers.

    Inspects:
    - ``Authentication-Results`` (consolidated per RFC 7601)
    - ``Received-SPF`` (per RFC 7208)
    - ``DKIM-Signature`` (presence implies attempted signing)

    Args:
        headers: Dict of header name -> value (or list of values).

    Returns:
        AuthenticationResults dataclass.
    """
    auth = AuthenticationResults()

    def _get(name: str) -> str:
        """Get header value(s) merged into a single lowercase string."""
        val = headers.get(name, "")
        if isinstance(val, list):
            return " ".join(val).lower()
        return val.lower()

    # --- Authentication-Results (may contain all three) ---
    ar_text = _get("Authentication-Results")
    if ar_text:
        spf_result, spf_detail = _extract_auth_result(ar_text, "spf")
        if spf_result != "none":
            auth.spf = spf_result
            auth.spf_detail = spf_detail

        dkim_result, dkim_detail = _extract_auth_result(ar_text, "dkim")
        if dkim_result != "none":
            auth.dkim = dkim_result
            auth.dkim_detail = dkim_detail

        dmarc_result, dmarc_detail = _extract_auth_result(ar_text, "dmarc")
        if dmarc_result != "none":
            auth.dmarc = dmarc_result
            auth.dmarc_detail = dmarc_detail

    # --- Received-SPF (overrides / supplements if more specific) ---
    spf_header = _get("Received-SPF")
    if spf_header and auth.spf == "not checked":
        # First word is the result
        first_word = spf_header.split()[0] if spf_header.split() else ""
        if first_word in _AUTH_RESULTS:
            auth.spf = first_word
            # Rest is detail
            detail_parts = spf_header.split(None, 1)
            auth.spf_detail = detail_parts[1].strip()[:200] if len(detail_parts) > 1 else ""

    # --- DKIM-Signature presence ---
    dkim_sig = _get("DKIM-Signature")
    if dkim_sig and auth.dkim == "not checked":
        # Signature is present but we cannot verify it without the public key.
        # Mark as 'present' so the analyst knows — not the same as 'pass'.
        auth.dkim = "present (unverified)"
        auth.dkim_detail = "DKIM-Signature header found; verification requires DNS lookup"

    return auth


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_headers(raw_headers: str) -> HeaderAnalysis:
    """Analyse raw email headers and extract threat-relevant information.

    Accepts:
    - Full .eml file content (with body)
    - Paste of raw headers only (without a body)

    Args:
        raw_headers: The raw email text (or just the header section).

    Returns:
        HeaderAnalysis with all extracted fields and findings.
    """
    analysis = HeaderAnalysis()

    # If the input looks like it has no blank-line body separator, append one
    # so email.parser does not choke on header-only input.
    if "\n\n" not in raw_headers and "\r\n\r\n" not in raw_headers:
        raw_headers = raw_headers + "\n\n"

    # Parse with the email standard library
    parser = email.parser.HeaderParser(policy=email.policy.compat32)
    msg = parser.parsestr(raw_headers)

    # ------------------------------------------------------------------
    # Address fields
    # ------------------------------------------------------------------
    from_raw = msg.get("From", "")
    if from_raw:
        analysis.from_address = parse_email_address(from_raw)

    rp_raw = msg.get("Return-Path", "")
    if rp_raw:
        analysis.return_path = parse_email_address(rp_raw)

    rt_raw = msg.get("Reply-To", "")
    if rt_raw:
        analysis.reply_to = parse_email_address(rt_raw)

    to_raw = msg.get("To", "")
    if to_raw:
        # Multiple recipients separated by commas
        for addr_part in to_raw.split(","):
            parsed = parse_email_address(addr_part.strip())
            if parsed:
                analysis.to_addresses.append(parsed)

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------
    analysis.subject = msg.get("Subject", None)
    analysis.date = msg.get("Date", None)
    analysis.message_id = msg.get("Message-ID", None)

    # ------------------------------------------------------------------
    # Received chain — collect all Received headers in order
    # (email module gives them newest-first, so we keep that order for display)
    # ------------------------------------------------------------------
    received_headers = msg.get_all("Received") or []
    for raw_received in received_headers:
        hop = parse_received_header(raw_received)
        analysis.received_chain.append(hop)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    # Build a flat dict of all headers for auth parsing
    headers_dict: dict = {}
    for key in msg.keys():
        existing = headers_dict.get(key)
        value = msg.get(key, "")
        if existing is None:
            headers_dict[key] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            headers_dict[key] = [existing, value]

    analysis.auth_results = parse_authentication_results(headers_dict)

    # ------------------------------------------------------------------
    # Extract all unique domains and IPs
    # ------------------------------------------------------------------
    seen_domains: set[str] = set()
    seen_ips: set[str] = set()

    def _add_domain(d: Optional[str]) -> None:
        if d and d not in seen_domains:
            seen_domains.add(d)
            analysis.domains.append(d)

    def _add_ip(ip: Optional[str]) -> None:
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            analysis.ips.append(ip)

    # Domains from address fields
    if analysis.from_address:
        _add_domain(analysis.from_address.domain)
    if analysis.return_path:
        _add_domain(analysis.return_path.domain)
    if analysis.reply_to:
        _add_domain(analysis.reply_to.domain)
    for addr in analysis.to_addresses:
        _add_domain(addr.domain)

    # IPs and domains from Received headers
    for hop in analysis.received_chain:
        _add_ip(hop.from_ip)
        _add_ip(hop.by_ip)
        # Extract hostnames' base domains
        for hostname in (hop.from_host, hop.by_host):
            if hostname:
                parts = hostname.split(".")
                if len(parts) >= 2:
                    base_domain = ".".join(parts[-2:])
                    _add_domain(base_domain)

    # URLs anywhere in the headers
    for value in msg.values():
        for url in _RE_URL.findall(value):
            if url not in analysis.urls:
                analysis.urls.append(url)

    # ------------------------------------------------------------------
    # Generate findings / warnings
    # ------------------------------------------------------------------
    _generate_findings(analysis)

    return analysis


def _generate_findings(analysis: HeaderAnalysis) -> None:
    """Populate analysis.findings with threat-relevant observations.

    Modifies the analysis object in place.
    """
    findings = analysis.findings

    # From vs Return-Path domain mismatch
    if analysis.from_address and analysis.return_path:
        if analysis.from_address.domain != analysis.return_path.domain:
            findings.append(
                f"From domain ({analysis.from_address.domain}) differs from "
                f"Return-Path domain ({analysis.return_path.domain}) — "
                "common indicator in phishing / spoofed emails"
            )

    # Reply-To differs from From
    if analysis.from_address and analysis.reply_to:
        if analysis.from_address.domain != analysis.reply_to.domain:
            findings.append(
                f"Reply-To domain ({analysis.reply_to.domain}) differs from "
                f"From domain ({analysis.from_address.domain}) — "
                "replies would go to a different domain"
            )

    # Authentication failures
    auth = analysis.auth_results
    if auth.spf.lower() in ("fail", "softfail"):
        findings.append(
            f"SPF check {auth.spf.upper()} — "
            "the sending IP is not authorised to send mail for this domain"
        )
    if auth.dkim.lower() == "fail":
        findings.append("DKIM signature FAILED — the message was modified or the key is invalid")
    if auth.dmarc.lower() == "fail":
        findings.append(
            "DMARC policy FAILED — combined SPF/DKIM alignment check did not pass"
        )

    # Multiple unique sender domains (From, Return-Path, Reply-To all different)
    sender_domains: set[str] = set()
    for addr in (analysis.from_address, analysis.return_path, analysis.reply_to):
        if addr:
            sender_domains.add(addr.domain)
    if len(sender_domains) >= 3:
        findings.append(
            f"Three different domains across sender fields: "
            f"{', '.join(sorted(sender_domains))} — highly suspicious"
        )

    # No authentication headers at all
    all_not_checked = (
        auth.spf == "not checked"
        and auth.dkim == "not checked"
        and auth.dmarc == "not checked"
    )
    if all_not_checked and analysis.received_chain:
        findings.append(
            "No authentication results found (SPF/DKIM/DMARC) — "
            "headers may have been stripped or are absent"
        )

    # Private / RFC1918 IP in the origin hop
    if analysis.received_chain:
        origin_hop = analysis.received_chain[-1]  # oldest hop = origin
        if origin_hop.from_ip:
            if _is_private_ip(origin_hop.from_ip):
                findings.append(
                    f"Origin hop has a private/internal IP ({origin_hop.from_ip}) — "
                    "the message was relayed from an internal network or headers were forged"
                )


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP address falls within RFC 1918 or loopback ranges."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
    except (ValueError, AttributeError):
        pass
    return False


# ---------------------------------------------------------------------------
# File-level entry point
# ---------------------------------------------------------------------------

def analyze_eml_file(file_path: Path) -> HeaderAnalysis:
    """Read an .eml file or a plain-text header dump and analyse it.

    Args:
        file_path: Path to a .eml file or a text file containing only headers.

    Returns:
        HeaderAnalysis with all extracted fields and findings.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If the file cannot be read.
        ValueError: If the file content cannot be parsed as email headers.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Try UTF-8 first; fall back to latin-1 (covers most legacy email encodings)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raw = file_path.read_text(encoding="latin-1")

    if not raw.strip():
        raise ValueError(f"File is empty: {file_path}")

    return analyze_headers(raw)
