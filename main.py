from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
import uvicorn
import logging
import os
from dotenv import load_dotenv

from app.scanner import scan_repo
from app.models import RepoInputModel, ScanResultModel, ErrorResponse
from app.logger import get_logger

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

@app.post("/scan/", response_model=ScanResultModel, responses={500: {"model": ErrorResponse}})
async def create_scan_request(repo_input: RepoInputModel, background_tasks: BackgroundTasks):
    """
    Accepts a GitHub repository URL or repository details and initiates a compliance scan.
    The scan is performed as a background task to avoid long request timeouts for comprehensive scans.
    However, for this initial version, we will run it synchronously to see immediate results/errors.
    
    **Note:** Ensure `OPENAI_API_KEY` is set in your environment.
    Optionally, `GITHUB_TOKEN` can be set for higher GitHub API rate limits.
    """
    logger.info(f"Received scan request for: {repo_input.repo_url or repo_input.repo_details}")

    # For now, run synchronously to simplify testing and immediate feedback.
    # In a production setting, you'd use background_tasks.add_task(scan_repo, repo_input)
    # and return an immediate response (e.g., a task ID).
    try:
        # Check for OPENAI_API_KEY
        if not os.getenv("OPENAI_API_KEY"):
            logger.error("OPENAI_API_KEY not found in environment variables.")
            raise HTTPException(
                status_code=500,
                detail="OPENAI_API_KEY is not set. Please set it in your environment variables."
            )
        
        logger.info("Starting repository scan...")
        scan_result = await scan_repo(repo_input)
        logger.info(f"Scan completed. Tier: {scan_result.tier}")
        return scan_result
    except ValueError as ve:
        logger.error(f"Validation error during scan: {ve}", exc_info=True)
        return JSONResponse(
            status_code=400, # Bad Request
            content=ErrorResponse(error="Validation Error", details=str(ve)).model_dump()
        )
    except HTTPException as he:
        # Re-raise HTTPExceptions directly (e.g., the one for missing API key)
        raise he
    except Exception as e:
        logger.error(f"An unexpected error occurred during the scan: {e}", exc_info=True)
        # Return a generic error response
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(error="Internal Server Error", details=str(e)).model_dump()
        )

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
