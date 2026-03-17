"""SQLAlchemy models for the cache database."""

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Column, DateTime, Index, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""

    pass


class CachedResult(Base):
    """Cached API result."""

    __tablename__ = "cached_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String(50), nullable=False)  # API source name
    indicator_type = Column(String(20), nullable=False)  # domain, ip, hash, etc.
    indicator_value = Column(String(500), nullable=False)  # The actual indicator
    result_json = Column(Text, nullable=False)  # JSON-serialized result
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    # Composite index for lookups
    __table_args__ = (
        Index(
            "ix_lookup",
            "source",
            "indicator_type",
            "indicator_value",
            unique=True,
        ),
        Index("ix_expires_at", "expires_at"),
    )

    def is_expired(self) -> bool:
        """Check if this cached result has expired."""
        return datetime.utcnow() > self.expires_at


class InvestigationLog(Base):
    """Log of investigations performed."""

    __tablename__ = "investigation_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(20), nullable=False)
    indicator_value = Column(String(500), nullable=False)
    sources_queried = Column(Text, nullable=False)  # JSON list of sources
    risk_score = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (Index("ix_investigation_created", "created_at"),)


class ApiQuotaUsage(Base):
    """Track daily API usage for quota management."""

    __tablename__ = "api_quota_usage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String(50), nullable=False)  # API source name
    date = Column(String(10), nullable=False)  # YYYY-MM-DD
    request_count = Column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("ix_quota_source_date", "source", "date", unique=True),
    )


def create_tables(database_url: str) -> None:
    """Create all tables in the database."""
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)


def get_session_maker(database_url: str) -> sessionmaker:
    """Get a session maker for the database."""
    engine = create_engine(database_url)
    return sessionmaker(bind=engine)
