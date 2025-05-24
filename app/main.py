from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks, WebSocket, Request # Added WebSocket
from starlette.websockets import WebSocketDisconnect # Added import
from .models import RepoInputModel, ScanResultModel, ScanGraphState, APIScanResponse, ScanRecordResponse, TaskStatusResponse, TaskSubmitResponse, ScanInitiatedResponse, ScanCompletedMessage, ErrorResponse, RiskTier, ScanPersistenceData # Import models
from .config import settings # Assuming config.py is in the same directory
from .logger import get_logger # Assuming logger.py is in the same directory
from .scanner import scan_repo # We will create scanner.py next
from .graph_orchestrator import get_graph_orchestrator, logger_orchestrator as graph_logger # For LangGraph
from .worker import scan_repository_task, get_task_status # Import Celery tasks
from typing import Any, List, Optional, Dict # Use Any for the graph type and List for response types
from app.db.session import get_db, engine # Corrected: Removed get_async_session
from app.db.base_class import Base # Import Base class for SQLAlchemy models
from sqlalchemy.ext.asyncio import AsyncSession # Import AsyncSession
from app.crud.crud_scan_record import get_scan_records_by_repo_url, get_all_scan_records, get_scan_record, get_scan_count_by_risk_tier # Import CRUD functions
from app.websocket_manager import ConnectionManager # Assuming ConnectionManager is here
import uuid # For generating scan IDs
import json # For serializing messages for WebSocket
from datetime import datetime # Added import for datetime
import os
import shutil

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
    logger.info(f"[ScanID: {scan_id}] Background graph scan task started for: {repo_input.repo_url or repo_input.repo_details}.")
    
    final_state_values = None  # To store output from __end__ event
    final_graph_state_snapshot: Optional[ScanGraphState] = None # To store the final state object
    temp_path_to_clean = None
    
    # Initialize current_state_obj with essential fields
    current_state_obj = ScanGraphState(
        scan_id=scan_id,
        input_model=repo_input,
        repo_info=None,
        commit_sha=None, 
        temp_repo_path=None, 
        discovered_files={},
        file_content_cache={},
        extracted_markdown_docs=[],
        parsed_openapi_specs=[],
        doc_summary=None,
        code_ast_analysis_results={},
        detailed_code_violations=[],
        grep_search_results=[],
        aggregated_code_signals=None,
        code_analysis_score=None,
        risk_tier=None,
        repository_files_for_embedding=[],
        embedding_upsert_status={},
        fuzzy_matches=[],
        checklist=None,
        final_api_response=None,
        persistence_data=None,
        persisted_record_id=None,
        error_messages=[]
    )

    try:
        repo_scan_graph = graph_orchestrator
        # Use the model_dump of current_state_obj for the initial input to the stream
        initial_graph_state_dict = current_state_obj.model_dump(exclude_none=False, exclude_unset=False)

        # Now that initial_graph_state_dict is formed, we will retrieve temp_repo_path from the state as it gets populated by nodes for cleanup.
        # This line might be problematic if temp_repo_path is not set at initialization
        temp_path_to_clean = initial_graph_state_dict.get('temp_repo_path')

        config = {"configurable": {"db_session": db}}

        logger.info(f"[ScanID: {scan_id}] Initializing graph stream with state (using astream_events): {json.dumps(initial_graph_state_dict, indent=2, default=str)}")
        logger.info(f"[ScanID: {scan_id}] Using config for stream: {config}")

        # Using astream_events for more detailed event information
        async for event in repo_scan_graph.astream_events(initial_graph_state_dict, config=config, version="v1"):
            event_type = event["event"]
            event_name = event["name"] # Corresponds to node name or special tags like __end__
            event_data = event["data"]
            run_id = event["run_id"]
            tags = event["tags"]
            
            logger.debug(f"[ScanID: {scan_id} RunID: {run_id}] Event: type='{event_type}', name='{event_name}', tags='{tags}', data_keys='{list(event_data.keys()) if isinstance(event_data, dict) else None}'")

            # Check for node completion events to send progress updates
            if event_type == "on_chain_end" and event_name != "__end__":
                if event_name == "LangGraph": # Enhanced logging for LangGraph event
                    logger.info(f"[ScanID: {scan_id} RunID: {run_id}] 'LangGraph' event (on_chain_end). Assigning current accumulated state as final.")
                    final_graph_state_snapshot = current_state_obj # Assign the maintained current_state_obj
                    break # Exit loop once the main graph is done

                # This is a node finishing, update current_state_obj
                node_output = event_data.get("output")
                if isinstance(node_output, dict):
                    try:
                        current_state_obj = current_state_obj.copy(update=node_output)
                        logger.info(f"[ScanID: {scan_id}] Node '{event_name}' completed. Updated current_state_obj.")
                        # Update temp_path_to_clean if the node modified temp_repo_path
                        if current_state_obj.temp_repo_path:
                            temp_path_to_clean = current_state_obj.temp_repo_path
                    except Exception as e:
                        logger.error(f"[ScanID: {scan_id}] Failed to update current_state_obj after node '{event_name}': {e}", exc_info=True)
                else:
                    logger.warning(f"[ScanID: {scan_id}] Node '{event_name}' output was not a dict. Type: {type(node_output)}. Skipping state update for this node.")

                node_state_after_execution = event_data.get("output") # This is fine for logging the raw output
                logger.info(f"[ScanID: {scan_id}] Node '{event_name}' completed (on_chain_end). Raw output keys: {list(node_state_after_execution.keys()) if isinstance(node_state_after_execution, dict) else 'N/A'}")
                
                node_detail_message = ""
                if event_name == "__start__":
                    node_detail_message = "Scan process initiated and initial setup complete."
                elif event_name.startswith("ChannelWrite<"):
                    try:
                        # Attempt to extract the target node for a more descriptive message
                        target_node_for_write = event_name.split('<')[1].split(',')[0]
                        node_detail_message = f"State updated after node '{target_node_for_write}'."
                    except IndexError:
                        node_detail_message = f"State updated after an internal step ('{event_name}')."
                else:
                    node_detail_message = f"Node '{event_name}' processing completed."

                progress_update = {
                    "status": "progress",
                    "node": event_name,
                    "detail": node_detail_message # Ensure detail is always populated
                }

                if isinstance(node_state_after_execution, dict):
                    current_score = node_state_after_execution.get("code_analysis_score")
                    if current_score is not None:
                        logger.info(f"[ScanID: {scan_id}] Node '{event_name}' state update: code_analysis_score={current_score}")
                        progress_update['current_score'] = current_score
                    
                    node_errors = node_state_after_execution.get("error_messages")
                    if node_errors:
                        progress_update["errors_from_node"] = node_errors

                    # Log count of detailed_code_violations for relevant nodes
                    if "detailed_code_violations" in node_state_after_execution:
                         logger.info(f"[ScanID: {scan_id}] Node '{event_name}' state update: {len(node_state_after_execution['detailed_code_violations'])} detailed_code_violations")

                await ws_manager.send_progress(
                    scan_id,
                    {
                        "event_type": "progress_update",
                        "data": progress_update
                    }
                )

            # Check for the final graph output event
            if event_type == "on_chain_end" and event_name == "__end__":
                logger.info(f"[ScanID: {scan_id} RunID: {run_id}] Received '__end__' event (on_chain_end). Full event_data: {json.dumps(event_data, indent=2, default=str)}") # Enhanced logging
                if isinstance(event_data, dict) and "output" in event_data:
                    final_state_values = event_data["output"] # This should be the full final graph state
                    logger.info(f"[ScanID: {scan_id}] Graph stream ended (on_chain_end for __end__). Final state captured. State keys: {list(final_state_values.keys()) if isinstance(final_state_values, dict) else 'Not a dict'}")
                else:
                    logger.warning(f"[ScanID: {scan_id}] Received __end__ event but 'output' missing or not dict in data.")
                # Do not break; let the stream naturally finish if there are other closing events.

        # --- Processing after the event stream has finished ---
        final_api_response = None
        if final_graph_state_snapshot:
            logger.info(f"[ScanID: {scan_id}] Processing final graph state for APIScanResponse.")
            if final_graph_state_snapshot.final_api_response:
                if isinstance(final_graph_state_snapshot.final_api_response, APIScanResponse):
                    final_api_response = final_graph_state_snapshot.final_api_response
                    logger.info(f"[ScanID: {scan_id}] Successfully retrieved APIScanResponse from final graph state.")
                else:
                    logger.warning(f"[ScanID: {scan_id}] final_api_response in final state is not an APIScanResponse object. Type: {type(final_graph_state_snapshot.final_api_response)}")    
            else:
                logger.warning(f"[ScanID: {scan_id}] final_api_response not found in the final graph state.")
        else:
            logger.error(f"[ScanID: {scan_id}] No final graph state snapshot was captured.")

        if not final_api_response:
            logger.error(f"[ScanID: {scan_id}] Graph execution did not yield a usable final APIScanResponse.")
            # Send error message via WebSocket if no specific response was generated
            await ws_manager.send_progress(
                scan_id,
                {
                    "event_type": "scan_error",
                    "error": "Graph execution did not yield a usable final APIScanResponse.",
                    "message": "An error occurred during the scan."
                }
            )
        else:
            # Ensure error_messages list exists if it was None
            if final_api_response.error_messages is None: final_api_response.error_messages = []
            # If there were no errors and list is empty, set to None for cleaner output
            if not final_api_response.error_messages: final_api_response.error_messages = None

            completed_message = ScanCompletedMessage(
                scan_id=scan_id,
                data=final_api_response
            )
            await ws_manager.send_progress(
                scan_id,
                {
                    "event_type": "scan_completed",
                    "data": completed_message.model_dump()
                }
            )
            logger.info(f"[ScanID: {scan_id}] Sent final 'scan_completed' WebSocket message with APIScanResponse.")

    except Exception as e:
        logger.error(f"[ScanID: {scan_id}] Error during graph scan task: {e}", exc_info=True)
        # Send error message via WebSocket if an unexpected exception occurs
        await ws_manager.send_progress(
            scan_id,
            {
                "event_type": "scan_error",
                "error": str(e),
                "message": "An unexpected error occurred during the scan."
            }
        )
    finally:
        logger.info(f"[ScanID: {scan_id}] Background graph scan task finished.")
        # Cleanup the temporary directory using the stored TemporaryDirectory object
        if current_state_obj and hasattr(current_state_obj, '_temp_dir_object') and current_state_obj._temp_dir_object:
            try:
                logger.info(f"[ScanID: {scan_id}] Cleaning up temporary directory: {current_state_obj._temp_dir_object.name}")
                current_state_obj._temp_dir_object.cleanup()
                logger.info(f"[ScanID: {scan_id}] Successfully cleaned up temporary directory.")
            except Exception as e:
                logger.error(f"[ScanID: {scan_id}] Error cleaning up temporary directory {current_state_obj._temp_dir_object.name}: {e}", exc_info=True)
        elif temp_path_to_clean: # Fallback for older logic if _temp_dir_object is somehow not set
            logger.warning(f"[ScanID: {scan_id}] _temp_dir_object not found in state, attempting cleanup with temp_path_to_clean: {temp_path_to_clean}")
            try:
                if os.path.exists(temp_path_to_clean):
                    shutil.rmtree(temp_path_to_clean)
                    logger.info(f"[ScanID: {scan_id}] Successfully cleaned up fallback temporary path: {temp_path_to_clean}")
            except Exception as e:
                logger.error(f"[ScanID: {scan_id}] Error cleaning up fallback temporary path {temp_path_to_clean}: {e}", exc_info=True)

        # Disconnect WebSocket if the manager supports per-scan_id disconnection
        # Or rely on client-side disconnect / timeout
        # await ws_manager.disconnect_scan_id(scan_id) # Example, if such a method exists
        logger.info(f"[ScanID: {scan_id}] WebSocket connections for this scan will be closed by client or timeout.")

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
