from sqlalchemy import Column, Integer, String, DateTime, JSON, Enum as SAEnum, Index
from sqlalchemy.dialects.postgresql import UUID # For UUID type
import uuid # For generating UUIDs
from datetime import datetime

from app.db.base_class import Base
from app.models import RiskTier # Import the Pydantic Enum for consistency

class ScanRecord(Base):
    """SQLAlchemy model for scan records."""
    __tablename__ = "scan_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repo_url = Column(String, index=True)
    repo_owner = Column(String, nullable=True)
    repo_name = Column(String, nullable=True)
    commit_sha = Column(String, nullable=True)
    risk_tier = Column(SAEnum(RiskTier, name='risk_tier_enum', create_type=False), nullable=True, index=True) # Use the Pydantic Enum
    checklist = Column(JSON, nullable=True) # Store checklist as JSON
    doc_summary = Column(JSON, nullable=True)  # Store doc_summary (list of strings) as JSON
    scan_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    error_messages = Column(JSON, nullable=True) # Store list of error strings as JSON

    # Create composite indexes for common query patterns
    __table_args__ = (
        # Index for repo_url + scan_timestamp for efficient history queries
        Index('ix_scan_records_repo_url_timestamp', 'repo_url', 'scan_timestamp'),
        # Index for risk_tier + scan_timestamp for filtered listing
        Index('ix_scan_records_risk_tier_timestamp', 'risk_tier', 'scan_timestamp'),
    )

    def __repr__(self):
        return f"<ScanRecord(id={self.id}, repo_url='{self.repo_url}', tier='{self.risk_tier}')>"
