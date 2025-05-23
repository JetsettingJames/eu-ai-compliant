from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks
from .models import RepoInputModel, ScanResultModel, ScanGraphState, APIScanResponse, ScanRecordResponse, TaskStatusResponse, TaskSubmitResponse # Import models
from .config import settings # Assuming config.py is in the same directory
from .logger import get_logger # Assuming logger.py is in the same directory
from .scanner import scan_repo # We will create scanner.py next
from .graph_orchestrator import get_graph_orchestrator, logger_orchestrator as graph_logger # For LangGraph
from .worker import scan_repository_task, get_task_status # Import Celery tasks
from typing import Any, List, Optional, Dict # Use Any for the graph type and List for response types
from app.db.session import get_db, engine # Import get_db and engine
from app.db.base_class import Base # Import Base class for SQLAlchemy models
from sqlalchemy.ext.asyncio import AsyncSession # Import AsyncSession
from app.crud.crud_scan_record import get_scan_records_by_repo_url, get_all_scan_records, get_scan_record, get_scan_count_by_risk_tier # Import CRUD functions

app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0", # You can manage versioning more dynamically if needed
    #openapi_url=f"{settings.API_V1_STR}/openapi.json" # If using API_V1_STR for all routes
)

logger = get_logger(__name__)
# Ensure logger level is set based on config
logger.setLevel(settings.LOG_LEVEL)

# --- Database Initialization Function --- #
async def create_db_and_tables():
    # Check if DATABASE_URL is not None before proceeding
    if not settings.DATABASE_URL:
        logger.warning("DATABASE_URL is not set. Skipping table creation.")
        return

    async with engine.begin() as conn:
        # For SQLite, metadata.create_all is fine for dev.
        # For Postgres, you'd use Alembic migrations.
        if "sqlite" in settings.DATABASE_URL:
            logger.info("Using SQLite, creating tables based on models...")
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Tables created (if they didn't exist).")
        else:
            logger.info("Using PostgreSQL, expecting tables to be managed by Alembic.")

@app.on_event("startup")
async def startup_event():
    logger.info("Application startup...")
    logger.info(f"App Name: {settings.APP_NAME}")
    # Create database tables if needed
    await create_db_and_tables()
    logger.info("Application startup complete.")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Application shutdown...")
    # Clean up resources, like database connections

@app.post(f"{settings.API_V1_STR}/scan", response_model=ScanResultModel)
async def trigger_scan_repository(input_data: RepoInputModel):
    """
    Endpoint to trigger a repository scan.

    Accepts either a 'repo_url' or 'repo_details' (owner, repo, branch).
    """
    logger.info(f"Received scan request for: {input_data.model_dump_json(indent=2)}")
    
    if not input_data.repo_url and not input_data.repo_details:
        raise HTTPException(
            status_code=400, 
            detail="Either 'repo_url' or 'repo_details' must be provided."
        )
    
    try:
        result = await scan_repo(input_data)
        return result
    except HTTPException as e:
        logger.error(f"HTTP Exception during scan: {e.detail}")
        raise e # Re-raise the HTTPException
    except Exception as e:
        logger.error(f"An unexpected error occurred during scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post(f"{settings.API_V1_STR}/graph-scan", response_model=APIScanResponse)
async def trigger_graph_scan_repository(
    repo_input: RepoInputModel,
    graph: Any = Depends(get_graph_orchestrator), 
    db: AsyncSession = Depends(get_db) 
) -> APIScanResponse:
    logger.info(f"Triggering graph scan for: {repo_input.repo_url or repo_input.repo_details}")

    try:
        # Get the compiled graph
        repo_scan_graph = graph
        
        # Initialize the graph state
        initial_graph_state = ScanGraphState(
            input_model=repo_input,
            repo_info=None,
            download_path=None,
            documentation_files=[],
            extracted_doc_content=None,
            doc_summary=None,
            code_analysis_results=None,
            aggregated_code_signals=None,
            risk_tier=None,
            checklist=None,
            final_api_response=None,
            persistence_data=None,
            persisted_record_id=None,
            db_session=db, 
            error_messages=[]
        )
        
        # Invoke the graph. The input is a dictionary where keys correspond to ScanGraphState fields.
        # For the initial call, we provide the whole initial state.
        # Subsequent node outputs will be merged into the state by LangGraph.
        # Use exclude_none=False and exclude_unset=False to include all fields, even those marked with exclude=True
        final_state_values = await repo_scan_graph.ainvoke(initial_graph_state.model_dump(exclude_none=False, exclude_unset=False, exclude=None))
        
        # The result from ainvoke will be the full state dictionary. We can re-validate it into our Pydantic model.
        # However, for StatefulGraph, the final_state *is* the ScanGraphState object itself if properly handled.
        # LangGraph's ainvoke with StatefulGraph typically returns the final state object or dict.
        # Let's assume it returns a dict that can be parsed into ScanGraphState for safety.
        if isinstance(final_state_values, dict):
            final_state = ScanGraphState(**final_state_values)
        elif isinstance(final_state_values, ScanGraphState):
            final_state = final_state_values # If ainvoke already returns the Pydantic model instance
        else:
            logger.error(f"Unexpected final state type from graph: {type(final_state_values)}")
            raise HTTPException(status_code=500, detail="Graph execution resulted in an unexpected state type.")

        # Log the entire final_state for debugging
        logger.info(f"Final state from graph: {final_state.model_dump_json(indent=2)}")

        if final_state.final_api_response:
            logger.info("Graph execution complete. Returning final API response.")
            return final_state.final_api_response
        else:
            # This case should ideally not be reached if prepare_final_response_node always runs
            logger.error("Graph execution completed, but no final_api_response was set in the state.")
            # Construct a fallback error response
            return APIScanResponse(
                error_messages=["Internal server error: Failed to generate final response."] + (final_state.error_messages or [])
            )

    except Exception as e:
        logger.error(f"An unexpected error occurred during graph scan: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error during graph scan: {str(e)}")

# A simple root endpoint for health check or basic info
@app.get("/")
async def read_root():
    logger.info("Root endpoint accessed.")
    return {"message": f"Welcome to {settings.APP_NAME}"}


@app.get(f"{settings.API_V1_STR}/scan-records", response_model=List[ScanRecordResponse])
async def list_scan_records(
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(100, ge=1, le=100, description="Maximum number of records to return"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier (e.g., 'minimal', 'limited', 'high', 'prohibited')"),
    db: AsyncSession = Depends(get_db)
) -> List[ScanRecordResponse]:
    """List all scan records with pagination and filtering."""
    logger.info(f"Retrieving scan records. skip={skip}, limit={limit}, risk_tier={risk_tier}")
    records = await get_all_scan_records(db, skip=skip, limit=limit, risk_tier=risk_tier)
    return records


@app.get(f"{settings.API_V1_STR}/scan-history", response_model=List[ScanRecordResponse])
async def get_scan_history(
    repo_url: str = Query(..., description="Repository URL to get scan history for"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    db: AsyncSession = Depends(get_db)
) -> List[ScanRecordResponse]:
    """Get scan history for a specific repository."""
    logger.info(f"Retrieving scan history for repo_url={repo_url}, limit={limit}")
    records = await get_scan_records_by_repo_url(db, repo_url=repo_url, limit=limit)
    return records


@app.get(f"{settings.API_V1_STR}/scan-records/{{scan_id}}", response_model=ScanRecordResponse)
async def get_scan_record_by_id(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
) -> ScanRecordResponse:
    """Get a specific scan record by ID."""
    logger.info(f"Retrieving scan record with ID={scan_id}")
    record = await get_scan_record(db, scan_id=scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan record with ID {scan_id} not found")
    return record


@app.post(f"{settings.API_V1_STR}/scan-async", response_model=TaskSubmitResponse)
async def trigger_async_scan(
    repo_input: RepoInputModel,
) -> TaskSubmitResponse:
    """Trigger an asynchronous repository scan."""
    logger.info(f"Submitting async scan for {repo_input.repo_url if repo_input.repo_url else repo_input.repo_details}")
    
    try:
        # Submit the task to Celery
        task = scan_repository_task.delay(repo_input.dict())
        
        return TaskSubmitResponse(
            task_id=task.id,
            status="submitted",
            message="Scan job submitted successfully",
            repo_url=str(repo_input.repo_url) if repo_input.repo_url else None
        )
    except Exception as e:
        logger.error(f"Error submitting async scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to submit scan job: {str(e)}")


@app.get(f"{settings.API_V1_STR}/scan-status/{{task_id}}", response_model=TaskStatusResponse)
async def check_scan_status(
    task_id: str,
) -> TaskStatusResponse:
    """Check the status of an asynchronous scan task."""
    logger.info(f"Checking status for task {task_id}")
    
    try:
        # Get task status from Celery
        status = get_task_status.delay(task_id).get(timeout=5)
        return TaskStatusResponse(**status)
    except Exception as e:
        logger.error(f"Error checking task status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to check task status: {str(e)}")


@app.get(f"{settings.API_V1_STR}/scan-statistics")
async def get_scan_statistics(
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get statistics about scan records."""
    logger.info("Retrieving scan statistics")
    
    try:
        # Get counts by risk tier
        risk_tier_counts = await get_scan_count_by_risk_tier(db)
        
        # Calculate total scans
        total_scans = sum(risk_tier_counts.values())
        
        return {
            "total_scans": total_scans,
            "risk_tier_distribution": risk_tier_counts,
            "last_updated": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error retrieving scan statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan statistics: {str(e)}")

# To run this app:
# Ensure you are in the project root directory
# Command: uvicorn app.main:app --reload
