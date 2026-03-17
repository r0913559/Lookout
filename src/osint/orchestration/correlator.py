"""Infrastructure correlation and relationship mapping."""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from osint.core.constants import IndicatorType
from osint.orchestration.investigator import InvestigationResult


@dataclass
class InfrastructureNode:
    """A node in the infrastructure graph."""

    value: str
    indicator_type: IndicatorType
    sources: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.value.lower(), self.indicator_type))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, InfrastructureNode):
            return False
        return (
            self.value.lower() == other.value.lower()
            and self.indicator_type == other.indicator_type
        )


@dataclass
class InfrastructureEdge:
    """A relationship edge between nodes."""

    source: InfrastructureNode
    target: InfrastructureNode
    relationship: str  # resolves_to, hosted_on, communicates_with, etc.
    confidence: float = 0.5
    data_source: str = ""


@dataclass
class InfrastructureGraph:
    """Graph representing infrastructure relationships."""

    nodes: dict[str, InfrastructureNode] = field(default_factory=dict)
    edges: list[InfrastructureEdge] = field(default_factory=list)

    def add_node(
        self,
        value: str,
        indicator_type: IndicatorType,
        source: Optional[str] = None,
        **metadata: Any,
    ) -> InfrastructureNode:
        """Add or update a node in the graph."""
        key = f"{indicator_type.value}:{value.lower()}"

        if key in self.nodes:
            node = self.nodes[key]
            if source and source not in node.sources:
                node.sources.append(source)
            node.metadata.update(metadata)
        else:
            node = InfrastructureNode(
                value=value,
                indicator_type=indicator_type,
                sources=[source] if source else [],
                metadata=metadata,
            )
            self.nodes[key] = node

        return node

    def add_edge(
        self,
        source_value: str,
        source_type: IndicatorType,
        target_value: str,
        target_type: IndicatorType,
        relationship: str,
        confidence: float = 0.5,
        data_source: str = "",
    ) -> InfrastructureEdge:
        """Add an edge between nodes."""
        source_node = self.add_node(source_value, source_type)
        target_node = self.add_node(target_value, target_type)

        edge = InfrastructureEdge(
            source=source_node,
            target=target_node,
            relationship=relationship,
            confidence=confidence,
            data_source=data_source,
        )
        self.edges.append(edge)

        return edge

    def get_related(
        self,
        value: str,
        indicator_type: IndicatorType,
        relationship: Optional[str] = None,
    ) -> list[InfrastructureNode]:
        """Get nodes related to a given node."""
        key = f"{indicator_type.value}:{value.lower()}"

        related = []
        for edge in self.edges:
            source_key = f"{edge.source.indicator_type.value}:{edge.source.value.lower()}"
            target_key = f"{edge.target.indicator_type.value}:{edge.target.value.lower()}"

            if relationship and edge.relationship != relationship:
                continue

            if source_key == key:
                related.append(edge.target)
            elif target_key == key:
                related.append(edge.source)

        return related

    def to_dict(self) -> dict[str, Any]:
        """Convert graph to dictionary format."""
        return {
            "nodes": [
                {
                    "id": f"{n.indicator_type.value}:{n.value}",
                    "value": n.value,
                    "type": n.indicator_type.value,
                    "sources": n.sources,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": f"{e.source.indicator_type.value}:{e.source.value}",
                    "target": f"{e.target.indicator_type.value}:{e.target.value}",
                    "relationship": e.relationship,
                    "confidence": e.confidence,
                    "data_source": e.data_source,
                }
                for e in self.edges
            ],
        }


class InfrastructureCorrelator:
    """
    Correlates infrastructure from investigation results.

    Builds a graph of relationships between indicators.
    """

    def __init__(self):
        """Initialize the correlator."""
        self.logger = logging.getLogger("osint.correlator")
        self.graph = InfrastructureGraph()

    def process_investigation(
        self,
        result: InvestigationResult,
    ) -> InfrastructureGraph:
        """
        Process investigation results to extract relationships.

        Args:
            result: Investigation result to process

        Returns:
            Updated infrastructure graph
        """
        # Add the main indicator as root node
        root = self.graph.add_node(
            value=result.indicator_value,
            indicator_type=result.indicator_type,
            source="investigation",
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
        )

        # Process each API result
        for source, api_result in result.results.items():
            if not api_result or not api_result.success:
                continue

            self._process_api_result(
                root_value=result.indicator_value,
                root_type=result.indicator_type,
                api_result=api_result,
                source_name=source.value,
            )

        return self.graph

    def _process_api_result(
        self,
        root_value: str,
        root_type: IndicatorType,
        api_result: Any,
        source_name: str,
    ) -> None:
        """Process a single API result for correlations."""
        # RDAP / WHOIS data
        if hasattr(api_result, "nameservers"):
            for ns in api_result.nameservers or []:
                self.graph.add_edge(
                    source_value=root_value,
                    source_type=root_type,
                    target_value=ns,
                    target_type=IndicatorType.DOMAIN,
                    relationship="nameserver",
                    confidence=0.9,
                    data_source=source_name,
                )

        # Certificate Transparency (crt.sh) subdomains
        if hasattr(api_result, "subdomains"):
            for subdomain in (api_result.subdomains or [])[:50]:
                self.graph.add_edge(
                    source_value=root_value,
                    source_type=root_type,
                    target_value=subdomain,
                    target_type=IndicatorType.DOMAIN,
                    relationship="subdomain",
                    confidence=0.95,
                    data_source=source_name,
                )

        # Shodan hostnames / domains
        if hasattr(api_result, "hostnames"):
            for hostname in api_result.hostnames or []:
                self.graph.add_edge(
                    source_value=root_value,
                    source_type=root_type,
                    target_value=hostname,
                    target_type=IndicatorType.DOMAIN,
                    relationship="resolves_to",
                    confidence=0.85,
                    data_source=source_name,
                )

        # Shodan domains
        if hasattr(api_result, "domains"):
            for domain in api_result.domains or []:
                if domain.lower() != root_value.lower():
                    self.graph.add_edge(
                        source_value=root_value,
                        source_type=root_type,
                        target_value=domain,
                        target_type=IndicatorType.DOMAIN,
                        relationship="associated_domain",
                        confidence=0.7,
                        data_source=source_name,
                    )

        # URLScan page IP
        if hasattr(api_result, "page_ip") and api_result.page_ip:
            self.graph.add_edge(
                source_value=root_value,
                source_type=root_type,
                target_value=api_result.page_ip,
                target_type=IndicatorType.IPV4,
                relationship="hosted_on",
                confidence=0.9,
                data_source=source_name,
            )

        # AlienVault related indicators
        if hasattr(api_result, "related_domains"):
            for domain in (api_result.related_domains or [])[:20]:
                self.graph.add_edge(
                    source_value=root_value,
                    source_type=root_type,
                    target_value=domain,
                    target_type=IndicatorType.DOMAIN,
                    relationship="threat_related",
                    confidence=0.6,
                    data_source=source_name,
                )

        if hasattr(api_result, "related_ips"):
            for ip in (api_result.related_ips or [])[:20]:
                ip_type = IndicatorType.IPV6 if ":" in ip else IndicatorType.IPV4
                self.graph.add_edge(
                    source_value=root_value,
                    source_type=root_type,
                    target_value=ip,
                    target_type=ip_type,
                    relationship="threat_related",
                    confidence=0.6,
                    data_source=source_name,
                )

        if hasattr(api_result, "related_hashes"):
            for hash_val in (api_result.related_hashes or [])[:20]:
                hash_type = self._detect_hash_type(hash_val)
                self.graph.add_edge(
                    source_value=root_value,
                    source_type=root_type,
                    target_value=hash_val,
                    target_type=hash_type,
                    relationship="threat_related",
                    confidence=0.6,
                    data_source=source_name,
                )

        # ThreatFox malware associations
        if hasattr(api_result, "malware_families"):
            for malware in api_result.malware_families or []:
                # Store malware as metadata on the root node
                root_key = f"{root_type.value}:{root_value.lower()}"
                if root_key in self.graph.nodes:
                    node = self.graph.nodes[root_key]
                    if "malware_families" not in node.metadata:
                        node.metadata["malware_families"] = []
                    if malware not in node.metadata["malware_families"]:
                        node.metadata["malware_families"].append(malware)

        # VirusTotal hash associations
        if hasattr(api_result, "sha256") and api_result.sha256:
            if root_type in (IndicatorType.MD5, IndicatorType.SHA1):
                self.graph.add_edge(
                    source_value=root_value,
                    source_type=root_type,
                    target_value=api_result.sha256,
                    target_type=IndicatorType.SHA256,
                    relationship="same_file",
                    confidence=1.0,
                    data_source=source_name,
                )

    def _detect_hash_type(self, hash_value: str) -> IndicatorType:
        """Detect hash type from length."""
        length = len(hash_value)
        if length == 32:
            return IndicatorType.MD5
        elif length == 40:
            return IndicatorType.SHA1
        else:
            return IndicatorType.SHA256

    def get_graph(self) -> InfrastructureGraph:
        """Get the current infrastructure graph."""
        return self.graph

    def reset(self) -> None:
        """Reset the graph."""
        self.graph = InfrastructureGraph()
