from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, Index, func
import uuid
import logging

from app.db.models.scan_record import ScanRecord
from app.models import ScanPersistenceData, ScanRecordResponse # Import Pydantic models
from app.services.cache_service import CacheService
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Initialize cache service for scan records
scan_record_cache = CacheService[Dict[str, Any]](dict, "scan_record")

async def create_scan_record(db: AsyncSession, *, scan_data: ScanPersistenceData) -> ScanRecord:
    """Create a new scan record in the database."""
    db_scan_record = ScanRecord(
        repo_url=scan_data.repo_url,
        repo_owner=scan_data.repo_owner,
        repo_name=scan_data.repo_name,
        commit_sha=scan_data.commit_sha,
        risk_tier=scan_data.risk_tier,
        checklist=scan_data.checklist,
        doc_summary=scan_data.doc_summary,
        scan_timestamp=scan_data.scan_timestamp, # Already set by Pydantic model
        error_messages=scan_data.error_messages
    )
    db.add(db_scan_record)
    # The commit will be handled by the get_db dependency's finally block
    # or by the calling service if more complex transaction management is needed.
    # For now, we assume get_db handles commit on success.
    await db.flush() # Flush to get ID if needed before commit
    await db.refresh(db_scan_record) # Refresh to get DB-generated values like ID
    
    # Convert to dict for caching if needed, but return the ORM object
    record_dict_for_cache = _scan_record_to_dict(db_scan_record)
    
    # Cache the new record
    await scan_record_cache.set(str(db_scan_record.id), record_dict_for_cache)
    
    # Invalidate any cached lists that might include this record
    await scan_record_cache.invalidate_pattern("list:*")
    if db_scan_record.repo_url:
        await scan_record_cache.invalidate_pattern(f"repo:{db_scan_record.repo_url}:*")
    
    return db_scan_record # Return the ORM instance

async def get_scan_record(db: AsyncSession, scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a scan record by its ID."""
    try:
        # Check cache first
        cached_record = await scan_record_cache.get(scan_id)
        if cached_record:
            logger.debug(f"Cache hit for scan record {scan_id}")
            return cached_record
        
        # Cache miss, query database
        logger.debug(f"Cache miss for scan record {scan_id}")
        uuid_obj = uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id
        result = await db.execute(select(ScanRecord).filter(ScanRecord.id == uuid_obj))
        record = result.scalars().first()
        
        if record:
            # Convert SQLAlchemy model to dict for Pydantic model
            record_dict = _scan_record_to_dict(record)
            # Cache the record for future requests
            await scan_record_cache.set(scan_id, record_dict)
            return record_dict
        return None
    except ValueError:
        # Invalid UUID format
        logger.warning(f"Invalid UUID format: {scan_id}")
        return None

async def get_scan_records_by_repo_url(db: AsyncSession, repo_url: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieve scan records by repository URL, ordered by most recent."""
    # Check cache first
    cache_key = f"repo:{repo_url}:limit:{limit}"
    cached_records = await scan_record_cache.get(cache_key)
    if cached_records:
        logger.debug(f"Cache hit for repo URL {repo_url} with limit {limit}")
        return cached_records
    
    # Cache miss, query database
    logger.debug(f"Cache miss for repo URL {repo_url} with limit {limit}")
    result = await db.execute(
        select(ScanRecord)
        .filter(ScanRecord.repo_url == repo_url)
        .order_by(ScanRecord.scan_timestamp.desc())
        .limit(limit)
    )
    records = result.scalars().all()
    
    # Convert SQLAlchemy models to dicts for Pydantic models
    record_dicts = [_scan_record_to_dict(record) for record in records]
    
    # Cache the results
    await scan_record_cache.set(cache_key, record_dicts)
    
    # Also cache individual records
    for record_dict in record_dicts:
        await scan_record_cache.set(record_dict["id"], record_dict)
    
    return record_dicts


async def get_all_scan_records(
    db: AsyncSession, 
    *, 
    skip: int = 0, 
    limit: int = 100,
    risk_tier: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Get all scan records with pagination and optional filtering.
    
    Args:
        db: Database session
        skip: Number of records to skip (for pagination)
        limit: Maximum number of records to return
        risk_tier: Optional filter by risk tier
        
    Returns:
        List of scan records ordered by scan timestamp (newest first)
    """
    # Build cache key based on parameters
    cache_key = f"list:skip:{skip}:limit:{limit}:risk_tier:{risk_tier or 'all'}"
    
    # Check cache first
    cached_records = await scan_record_cache.get(cache_key)
    if cached_records:
        logger.debug(f"Cache hit for scan records list with key {cache_key}")
        return cached_records
    
    # Cache miss, query database
    logger.debug(f"Cache miss for scan records list with key {cache_key}")
    query = select(ScanRecord).order_by(ScanRecord.scan_timestamp.desc())
    
    if risk_tier:
        query = query.filter(ScanRecord.risk_tier == risk_tier)
        
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    records = result.scalars().all()
    
    # Convert SQLAlchemy models to dicts for Pydantic models
    record_dicts = [_scan_record_to_dict(record) for record in records]
    
    # Cache the results
    await scan_record_cache.set(cache_key, record_dicts)
    
    # Also cache individual records
    for record_dict in record_dicts:
        await scan_record_cache.set(record_dict["id"], record_dict)
    
    return record_dicts


def _scan_record_to_dict(record: ScanRecord) -> Dict[str, Any]:
    """Convert a ScanRecord SQLAlchemy model to a dictionary for Pydantic model."""
    return {
        "id": str(record.id),  # Convert UUID to string
        "repo_url": record.repo_url,
        "repo_owner": record.repo_owner,
        "repo_name": record.repo_name,
        "commit_sha": record.commit_sha,
        "risk_tier": record.risk_tier,
        "checklist": record.checklist,
        "doc_summary": record.doc_summary,
        "scan_timestamp": record.scan_timestamp.isoformat(), # Convert datetime to ISO string
        "error_messages": record.error_messages
    }


async def get_scan_count_by_risk_tier(db: AsyncSession) -> Dict[str, int]:
    """Get count of scan records by risk tier.
    
    Returns:
        Dictionary with risk tier as key and count as value
    """
    # Check cache first
    cache_key = "stats:risk_tier_counts"
    cached_counts = await scan_record_cache.get(cache_key)
    if cached_counts:
        logger.debug("Cache hit for risk tier counts")
        return cached_counts
    
    # Cache miss, query database
    logger.debug("Cache miss for risk tier counts")
    result = await db.execute(
        select(ScanRecord.risk_tier, func.count(ScanRecord.id))
        .group_by(ScanRecord.risk_tier)
    )
    counts = {tier: count for tier, count in result.all()}
    
    # Cache the results (with a shorter TTL for stats)
    await scan_record_cache.set(cache_key, counts)
    
    return counts
