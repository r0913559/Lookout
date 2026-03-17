"""Report models."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from osint.core.constants import IndicatorType, RiskLevel


class TimelineEvent(BaseModel):
    """A single event in the investigation timeline."""

    timestamp: datetime
    source: str
    event_type: str  # first_seen, last_seen, detection, etc.
    description: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RelatedIndicator(BaseModel):
    """An indicator related to the investigated one."""

    value: str
    indicator_type: IndicatorType
    relationship: str  # resolves_to, hosted_on, communicates_with, etc.
    source: str
    confidence: float = 0.5  # 0-1


class InvestigationReport(BaseModel):
    """Complete investigation report."""

    # Investigation metadata
    report_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    analyst: Optional[str] = None

    # Target indicator
    indicator_value: str
    indicator_type: IndicatorType

    # Risk assessment
    risk_score: Optional[float] = None
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_summary: Optional[str] = None

    # Executive summary
    executive_summary: str = ""
    key_findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    # Timeline
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # Related indicators
    related_indicators: list[RelatedIndicator] = Field(default_factory=list)

    # Source data
    sources_queried: list[str] = Field(default_factory=list)
    sources_with_data: list[str] = Field(default_factory=list)
    sources_failed: list[str] = Field(default_factory=list)
    source_errors: dict[str, str] = Field(default_factory=dict)

    # Raw results (optional, for detailed reports)
    raw_results: dict[str, Any] = Field(default_factory=dict)

    # Tags and notes
    tags: list[str] = Field(default_factory=list)
    notes: Optional[str] = None

    def add_timeline_event(
        self,
        source: str,
        event_type: str,
        description: str,
        timestamp: Optional[datetime] = None,
        **metadata: Any,
    ) -> None:
        """Add an event to the timeline."""
        self.timeline.append(
            TimelineEvent(
                timestamp=timestamp or datetime.utcnow(),
                source=source,
                event_type=event_type,
                description=description,
                metadata=metadata,
            )
        )
        # Keep timeline sorted (normalize to naive UTC for comparison)
        self.timeline.sort(
            key=lambda e: e.timestamp.replace(tzinfo=None)
            if e.timestamp else datetime.min
        )

    def add_related_indicator(
        self,
        value: str,
        indicator_type: IndicatorType,
        relationship: str,
        source: str,
        confidence: float = 0.5,
    ) -> None:
        """Add a related indicator."""
        self.related_indicators.append(
            RelatedIndicator(
                value=value,
                indicator_type=indicator_type,
                relationship=relationship,
                source=source,
                confidence=confidence,
            )
        )

    def generate_risk_summary(self) -> str:
        """Generate a human-readable risk summary."""
        if self.risk_level == RiskLevel.CRITICAL:
            return (
                f"CRITICAL THREAT: This {self.indicator_type.value} shows strong indicators "
                f"of malicious activity across multiple sources."
            )
        elif self.risk_level == RiskLevel.HIGH:
            return (
                f"HIGH RISK: This {self.indicator_type.value} has been flagged by multiple "
                f"threat intelligence sources."
            )
        elif self.risk_level == RiskLevel.MEDIUM:
            return (
                f"MODERATE RISK: This {self.indicator_type.value} shows some suspicious "
                f"characteristics that warrant further investigation."
            )
        elif self.risk_level == RiskLevel.LOW:
            return (
                f"LOW RISK: This {self.indicator_type.value} shows minimal suspicious "
                f"indicators but should be monitored."
            )
        elif self.risk_level == RiskLevel.CLEAN:
            return (
                f"CLEAN: This {self.indicator_type.value} appears to be benign based on "
                f"available threat intelligence."
            )
        else:
            return (
                f"UNKNOWN: Insufficient data to assess the risk of this "
                f"{self.indicator_type.value}."
            )
