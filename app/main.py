from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks, WebSocket, Request # Added WebSocket
from .models import RepoInputModel, ScanResultModel, ScanGraphState, APIScanResponse, ScanRecordResponse, TaskStatusResponse, TaskSubmitResponse, ScanInitiatedResponse # Import models
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
from app.websocket_manager import ConnectionManager # Assuming ConnectionManager is here
import uuid # For generating scan IDs
import json # For serializing messages for WebSocket
from datetime import datetime # Added import for datetime

app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0", # You can manage versioning more dynamically if needed
    #openapi_url=f"{settings.API_V1_STR}/openapi.json" # If using API_V1_STR for all routes
)

logger = get_logger(__name__)
# Ensure logger level is set based on config
logger.setLevel(settings.LOG_LEVEL)

# --- WebSocket Connection Manager --- #
manager = ConnectionManager() # Instantiate the connection manager

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

# Helper function to run the graph scan in the background
async def _run_graph_scan_task(
    scan_id: str,
    repo_input: RepoInputModel,
    graph_orchestrator: Any, # Renamed from 'graph' to avoid conflict with langgraph's graph object
    db: AsyncSession,
    ws_manager: ConnectionManager
):
    logger.info(f"[ScanID: {scan_id}] Background graph scan task started for: {repo_input.repo_url or repo_input.repo_details}")
    final_response_data = {}
    try:
        repo_scan_graph = graph_orchestrator
        initial_graph_state = ScanGraphState(
            input_model=repo_input,
            repo_info=None,
            # download_path=None, # download_path is not a field in ScanGraphState
            commit_sha=None, # Added commit_sha initialization
            temp_repo_path=None, # Added temp_repo_path initialization
            discovered_files={},
            file_content_cache={},
            extracted_markdown_docs=[],
            parsed_openapi_specs=[],
            doc_summary=None,
            code_ast_analysis_results={},
            grep_search_results=[],
            aggregated_code_signals=None,
            risk_tier=None,
            repository_files_for_embedding=[],
            embedding_upsert_status={},
            fuzzy_matches=[],
            checklist=None,
            final_api_response=None,
            persistence_data=None,
            persisted_record_id=None,
            db_session=db,
            error_messages=[]
        )

        final_state_values = await repo_scan_graph.ainvoke(initial_graph_state.model_dump(exclude_none=False, exclude_unset=False, exclude=None))

        if isinstance(final_state_values, dict):
            final_state = ScanGraphState(**final_state_values)
        elif isinstance(final_state_values, ScanGraphState):
            final_state = final_state_values
        else:
            logger.error(f"[ScanID: {scan_id}] Unexpected final state type from graph: {type(final_state_values)}")
            # Prepare an error response to send over WebSocket
            final_response_data = APIScanResponse(
                error_messages=["Graph execution resulted in an unexpected state type."]
            ).model_dump()
            await ws_manager.send_progress(scan_id, {"status": "error", "data": final_response_data})
            return

        logger.info(f"[ScanID: {scan_id}] Final state from graph: {final_state.model_dump_json(indent=2)}")

        if final_state.final_api_response:
            logger.info(f"[ScanID: {scan_id}] Graph execution complete. Preparing final API response for WebSocket.")
            final_response_data = final_state.final_api_response.model_dump()
            await ws_manager.send_progress(scan_id, {"status": "completed", "data": final_response_data})
        else:
            logger.error(f"[ScanID: {scan_id}] Graph execution completed, but no final_api_response was set.")
            final_response_data = APIScanResponse(
                error_messages=["Internal server error: Failed to generate final response."] + (final_state.error_messages or [])
            ).model_dump()
            await ws_manager.send_progress(scan_id, {"status": "error", "data": final_response_data})

    except Exception as e:
        logger.error(f"[ScanID: {scan_id}] An unexpected error occurred during background graph scan: {str(e)}", exc_info=True)
        final_response_data = APIScanResponse(
            error_messages=[f"Internal server error during graph scan: {str(e)}"]
        ).model_dump()
        await ws_manager.send_progress(scan_id, {"status": "error", "data": final_response_data})
    finally:
        logger.info(f"[ScanID: {scan_id}] Background graph scan task finished.")
        # Optionally, close the specific WebSocket connection if it's managed per scan_id
        # await ws_manager.disconnect_scan_id(scan_id) # Example if such a method exists


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

@app.post(f"{settings.API_V1_STR}/graph-scan", response_model=ScanInitiatedResponse) # Changed response_model
async def trigger_graph_scan_repository(
    repo_input: RepoInputModel,
    background_tasks: BackgroundTasks, # Added BackgroundTasks
    graph_orchestrator: Any = Depends(get_graph_orchestrator), # Renamed 'graph' to 'graph_orchestrator'
    db: AsyncSession = Depends(get_db),
    # ws_manager: ConnectionManager = Depends(get_connection_manager) # Or use global 'manager'
) -> ScanInitiatedResponse:
    scan_id = str(uuid.uuid4())
    websocket_url = f"/ws/scan_progress/{scan_id}"
    logger.info(f"[ScanID: {scan_id}] Triggering graph scan for: {repo_input.repo_url or repo_input.repo_details}. WebSocket URL: {websocket_url}")

    # Add the graph scan execution to background tasks
    background_tasks.add_task(
        _run_graph_scan_task,
        scan_id,
        repo_input,
        graph_orchestrator,
        db,
        manager # Using the global manager instance
    )

    return ScanInitiatedResponse(
        scan_id=scan_id,
        message="Scan initiated. Connect to WebSocket for progress.",
        websocket_url=websocket_url
    )


# A simple root endpoint for health check or basic info
@app.get("/", tags=["General"])
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

# WebSocket endpoint for scan progress
@app.websocket("/ws/scan_progress/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)  # Corrected order: websocket, then scan_id
    logger.info(f"Client connected to WebSocket for scan_id: {scan_id}")
    try:
        while True:
            # Keep the connection alive, or handle client messages if any
            data = await websocket.receive_text() 
            logger.info(f"[WS ScanID: {scan_id}] Received from client: {data}")
            # Echo back or process client message if needed
            # await manager.send_personal_message(f"Echo: {data}", websocket)
    except WebSocketDisconnect:
        logger.info(f"Client disconnected from WebSocket for scan_id: {scan_id}")
        manager.disconnect(scan_id, websocket)
    except Exception as e:
        logger.error(f"Error in WebSocket for scan_id {scan_id}: {e}", exc_info=True)
        manager.disconnect(scan_id, websocket)


# To run this app:
# Ensure you are in the project root directory
# Command: uvicorn app.main:app --reload
