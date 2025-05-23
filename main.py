from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
import uvicorn
import logging
import os
from dotenv import load_dotenv
import uuid

from app.scanner import scan_repo
from app.models import RepoInputModel, ScanResultModel, ErrorResponse, ScanInitiatedResponse
from app.logger import get_logger
from app.websocket_manager import manager

# Load environment variables from .env file
load_dotenv()

app = FastAPI(
    title="EU AI Act Compliance Scanner",
    description="Scans GitHub repositories for potential EU AI Act compliance considerations.",
    version="0.1.0"
)

logger = get_logger(__name__)

# Configure logging for Uvicorn if running directly
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting FastAPI application with Uvicorn...")

@app.post("/scan/", response_model=ScanInitiatedResponse, responses={500: {"model": ErrorResponse}})
async def create_scan_request(repo_input: RepoInputModel, background_tasks: BackgroundTasks):
    """
    Accepts a GitHub repository URL or repository details and initiates a compliance scan.
    The scan is performed as a background task. A scan_id is returned for tracking progress via WebSocket.
    
    **Note:** Ensure `OPENAI_API_KEY` is set in your environment.
    Optionally, `GITHUB_TOKEN` can be set for higher GitHub API rate limits.
    """
    logger.info(f"Received scan request for: {repo_input.repo_url or repo_input.repo_details}")

    # Check for OPENAI_API_KEY before starting background task
    if not os.getenv("OPENAI_API_KEY"):
        logger.error("OPENAI_API_KEY not found in environment variables.")
        raise HTTPException(
            status_code=500,
            detail="OPENAI_API_KEY is not set. Please set it in your environment variables."
        )

    scan_id = str(uuid.uuid4())
    logger.info(f"Generated scan_id: {scan_id} for the request.")

    try:
        # Add the scan_repo task to background tasks
        # Pass the manager instance for progress reporting
        background_tasks.add_task(scan_repo, repo_input, scan_id=scan_id, ws_manager=manager)
        
        logger.info(f"Scan {scan_id} added to background tasks.")
        return ScanInitiatedResponse(
            scan_id=scan_id,
            message="Scan initiated. Connect to WebSocket for progress updates.",
            websocket_url=f"/ws/scan_progress/{scan_id}" # Provide the WebSocket URL
        )
    except ValueError as ve: # This might catch issues during initial input validation if any
        logger.error(f"Validation error before starting scan {scan_id}: {ve}", exc_info=True)
        return JSONResponse(
            status_code=400, # Bad Request
            content=ErrorResponse(error="Validation Error", details=str(ve)).model_dump()
        )
    except Exception as e: # Catch any other unexpected errors during task submission
        logger.error(f"An unexpected error occurred while initiating scan {scan_id}: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(error="Internal Server Error", details=f"Could not initiate scan: {str(e)}").model_dump()
        )

@app.websocket("/ws/scan_progress/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)
    try:
        while True:
            # Keep the connection alive. Client can send messages if needed (e.g., a ping).
            # For now, we just wait for disconnect.
            data = await websocket.receive_text() 
            # You could handle client messages here, e.g., pings or specific requests
            # logger.debug(f"Received from client for {scan_id}: {data}")
            # await manager.send_progress(scan_id, {"status": "pong", "client_message": data}) # Example echo/pong
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)
        logger.info(f"WebSocket disconnected for scan_id: {scan_id} (client closed connection)")
    except Exception as e:
        # Log other exceptions that might occur on the WebSocket connection
        logger.error(f"Error on WebSocket for scan_id {scan_id}: {e}", exc_info=True)
        manager.disconnect(websocket, scan_id) # Ensure disconnection on error

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# To run the server (from the project root directory):
# uvicorn main:app --reload

# Example curl request:
# curl -X POST "http://127.0.0.1:8000/scan/" -H "Content-Type: application/json" -d '{
# "repo_url": "https://github.com/openai/openai-python"
# }'

if __name__ == "__main__":
    # This part is for running with `python main.py` which is not typical for production
    # Uvicorn is preferred for development and production
    uvicorn.run(app, host="0.0.0.0", port=8000)
