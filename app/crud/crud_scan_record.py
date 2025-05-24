from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc, Index, func
import uuid
import logging

from app.db.models.scan_record import ScanRecord
from app.models import ScanPersistenceData, ScanRecordResponse, ComplianceObligation, ComplianceChecklistItem, RiskTier # Import Pydantic models
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

async def get_all_obligations_with_checklist_items(db: AsyncSession, risk_tier_categories: Optional[List[str]] = None) -> List[ComplianceObligation]:
    """Placeholder function to return a hardcoded list of compliance obligations and checklist items."""
    logger.info("CRUD: Using placeholder get_all_obligations_with_checklist_items")
    # This is a placeholder. In a real scenario, this would query the database.
    obligations_data = [
        {
            "id": "HUMAN_OVERSIGHT_ART_14",
            "title": "Human Oversight (Article 14)",
            "description": "High-risk AI systems shall be designed and developed in such a way...that they can be effectively overseen by natural persons during the period in which the AI system is in use.",
            "article_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206#d1e1987-1-1",
            "risk_tier_categories_applies_to": [RiskTier.HIGH.value], # Indicates this obligation primarily applies to HIGH risk
            "checklist_items": [
                {
                    "id": "HO-MEASURES-DESIGN",
                    "title": "Appropriate human oversight measures",
                    "description": "Ensure human oversight measures are appropriate to the risks posed by the AI system.",
                    "assessment_details": "Initial placeholder assessment.",
                    "status": "pending_assessment",
                    "evidence_needed": "Design documents, UI/UX specifications showing oversight controls.",
                    "risk_level_specific": [RiskTier.HIGH.value] # This item is specific to HIGH risk
                },
                {
                    "id": "HO-INTERVENTION-CAPABILITY",
                    "title": "Human intervention capability",
                    "description": "Ensure natural persons to whom human oversight is assigned have the necessary competence, training and authority.",
                    "assessment_details": "Initial placeholder assessment.",
                    "status": "pending_assessment",
                    "evidence_needed": "System documentation, operational procedures.",
                    "risk_level_specific": [RiskTier.HIGH.value]
                }
            ]
        },
        {
            "id": "DATA_GOVERNANCE_ART_10",
            "title": "Data and data governance (Article 10)",
            "description": "High-risk AI systems which make use of techniques involving the training of models with data shall be developed on the basis of training, validation and testing data sets...",
            "article_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206#d1e1603-1-1",
            "risk_tier_categories_applies_to": [RiskTier.HIGH.value, RiskTier.LIMITED.value], # Applies to HIGH and LIMITED
            "checklist_items": [
                {
                    "id": "TD-QUALITY-CRITERIA",
                    "title": "Training data quality criteria",
                    "description": "Ensure training, validation, and testing data sets are relevant, representative, free of errors and complete.",
                    "assessment_details": "Initial placeholder assessment.",
                    "status": "pending_assessment",
                    "evidence_needed": "Data sheets, data quality reports, dataset analysis.",
                    "risk_level_specific": [RiskTier.HIGH.value, RiskTier.LIMITED.value]
                }
            ]
        },
        {
            "id": "TRANSPARENCY_ART_13",
            "title": "Transparency and provision of information to users (Article 13)",
            "description": "High-risk AI systems shall be designed and developed in such a way to ensure that their operation is sufficiently transparent to enable users to interpret the system’s output and use it appropriately.",
            "article_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206#d1e1883-1-1",
            "risk_tier_categories_applies_to": [RiskTier.HIGH.value, RiskTier.LIMITED.value, RiskTier.MINIMAL.value], # Applies to all
            "checklist_items": [
                {
                    "id": "TP-USER-INFO-OUTPUT",
                    "title": "User information on output interpretation",
                    "description": "Provide users with clear and concise information about the AI system's capabilities, limitations, and expected performance to enable them to interpret and use the output appropriately.",
                    "assessment_details": "Initial placeholder assessment.",
                    "status": "pending_assessment",
                    "evidence_needed": "User manuals, system documentation, in-app guidance.",
                    "risk_level_specific": None # Applies to all tiers this obligation is for
                }
            ]
        }
    ]

    # Filter obligations based on risk_tier_categories if provided
    if risk_tier_categories:
        filtered_obligations_data = []
        for obl_data in obligations_data:
            # Include if the obligation applies to any of the requested risk tiers
            # or if the obligation applies to all tiers (risk_tier_categories_applies_to is None or empty)
            applies_to = obl_data.get("risk_tier_categories_applies_to")
            if not applies_to: # If applies_to is not defined, assume it's general
                filtered_obligations_data.append(obl_data)
            elif any(tier in applies_to for tier in risk_tier_categories):
                filtered_obligations_data.append(obl_data)
        obligations_data_to_process = filtered_obligations_data
    else:
        # If no specific risk_tier_categories are requested, return all obligations (or a default set)
        obligations_data_to_process = obligations_data

    db_obligations: List[ComplianceObligation] = []
    for obligation_dict in obligations_data_to_process:
        checklist_items: List[ComplianceChecklistItem] = []
        for item_dict in obligation_dict.get("checklist_items", []):
            # Filter checklist items based on risk_tier_categories as well, if item has specific risk levels
            item_risk_levels = item_dict.get("risk_level_specific")
            include_item = True # Default to include
            if risk_tier_categories and item_risk_levels:
                # Only include if the item is specific to one of the requested risk tiers
                if not any(tier in item_risk_levels for tier in risk_tier_categories):
                    include_item = False
            
            if include_item:
                checklist_items.append(ComplianceChecklistItem(
                    item_id=item_dict["id"],
                    title=item_dict["title"],
                    description=item_dict["description"],
                    obligation_id=obligation_dict["id"],
                    obligation_title=obligation_dict["title"],
                    assessment_details=item_dict.get("assessment_details"),
                    status=item_dict.get("status", "pending_assessment"),
                    evidence_needed=item_dict.get("evidence_needed"),
                    risk_level_specific=item_dict.get("risk_level_specific"), # Store as list of strings
                    reference_article=item_dict.get("reference_article"),
                    category_type=item_dict.get("category_type")
                ))
        
        # Only add obligation if it has relevant checklist items after filtering
        if checklist_items:
            db_obligations.append(ComplianceObligation(
                id=obligation_dict["id"],
                title=obligation_dict["title"],
                description=obligation_dict["description"],
                article_url=obligation_dict.get("article_url"),
                risk_tier_categories=obligation_dict.get("risk_tier_categories_applies_to"), # Store as list of strings
                checklist_items=checklist_items
            ))
            
    return db_obligations

async def update_scan_record_with_results(
    db: AsyncSession,
    scan_id: str,
    risk_tier: Optional[RiskTier],
    checklist: Optional[List[Dict[str, Any]]],
    doc_summary: Optional[List[str]],
    error_messages: Optional[List[str]],
    # Add other fields from APIScanResponse or state as needed, e.g., code_analysis_score
    # code_analysis_score: Optional[float] # Example if we decide to store it
) -> Optional[ScanRecord]:
    """Update an existing scan record with the final scan results."""
    try:
        uuid_obj = uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id
        result = await db.execute(select(ScanRecord).filter(ScanRecord.id == uuid_obj))
        db_scan_record = result.scalars().first()

        if not db_scan_record:
            logger.warning(f"Scan record with ID {scan_id} not found for update.")
            return None

        # Update fields
        if risk_tier is not None:
            db_scan_record.risk_tier = risk_tier
        if checklist is not None:
            db_scan_record.checklist = checklist # Stored as JSON
        if doc_summary is not None:
            db_scan_record.doc_summary = doc_summary # Stored as JSON
        if error_messages is not None:
            db_scan_record.error_messages = error_messages # Stored as JSON
        # if code_analysis_score is not None: # Example
        #     db_scan_record.code_analysis_score = code_analysis_score
        
        # The scan_timestamp is set at creation and typically not updated here.
        # repo_url, owner, name, commit_sha are also set at creation.

        await db.flush() # Apply changes to the session
        await db.refresh(db_scan_record) # Refresh to get any DB-side changes

        logger.info(f"Successfully updated scan record {scan_id} with results.")

        # Cache invalidation
        # Invalidate the specific record's cache
        await scan_record_cache.delete(str(db_scan_record.id))
        # Invalidate any list caches that might be affected
        await scan_record_cache.invalidate_pattern("list:*")
        if db_scan_record.repo_url:
            await scan_record_cache.invalidate_pattern(f"repo:{db_scan_record.repo_url}:*")
        
        return db_scan_record

    except ValueError:
        logger.warning(f"Invalid UUID format for scan_id: {scan_id} during update.")
        return None
    except Exception as e:
        logger.error(f"Error updating scan record {scan_id}: {str(e)}", exc_info=True)
        # Depending on transaction handling, a rollback might be needed here
        # if not handled by the get_db context manager.
        await db.rollback() # Explicitly rollback on error within this function
        raise # Re-raise the exception to be handled by the caller or global error handler
