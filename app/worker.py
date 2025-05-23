"""
Celery worker configuration for handling long-running tasks.
"""
import logging
from celery import Celery
import uuid
from typing import Dict, Any, Optional

from app.config import settings
from app.models import RepoInputModel, ScanPersistenceData
from app.graph_orchestrator import get_graph_orchestrator
from app.db.session import get_db_context

# Configure logging
logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "eu_ai_compliant",
    broker=settings.REDIS_URL or "redis://localhost:6379/0",
    backend=settings.REDIS_URL or "redis://localhost:6379/0"
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,  # 10 minutes max for a task
    worker_max_tasks_per_child=10,  # Restart worker after 10 tasks to prevent memory leaks
)

@celery_app.task(bind=True, name="scan_repository")
def scan_repository_task(self, repo_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Celery task to scan a repository asynchronously.
    
    Args:
        repo_input: Dictionary representation of RepoInputModel
        
    Returns:
        Dictionary with task result information
    """
    task_id = self.request.id
    logger.info(f"Starting repository scan task {task_id}")
    
    try:
        # Convert dict to RepoInputModel
        input_model = RepoInputModel.parse_obj(repo_input)
        
        # Get the graph orchestrator
        graph = get_graph_orchestrator()
        
        # Create a database session context manager
        db_context = get_db_context()
        
        # Execute the graph with database session
        with db_context() as db:
            # Add task_id to inputs for tracking
            inputs = {
                "input_model": input_model,
                "db_session": db,
                "task_id": task_id
            }
            
            # Run the graph
            result = graph.invoke(inputs)
            
            # Extract relevant information for the response
            response_data = {
                "task_id": task_id,
                "status": "completed",
                "repo_url": str(input_model.repo_url) if input_model.repo_url else None,
                "risk_tier": result.get("risk_tier"),
                "persisted_record_id": str(result.get("persisted_record_id")) if result.get("persisted_record_id") else None,
            }
            
            logger.info(f"Repository scan task {task_id} completed successfully")
            return response_data
            
    except Exception as e:
        logger.error(f"Error in repository scan task {task_id}: {str(e)}", exc_info=True)
        return {
            "task_id": task_id,
            "status": "failed",
            "error": str(e)
        }

@celery_app.task(bind=True, name="get_task_status")
def get_task_status(self, task_id: str) -> Dict[str, Any]:
    """
    Get the status of a task.
    
    Args:
        task_id: The ID of the task to check
        
    Returns:
        Dictionary with task status information
    """
    try:
        # Get the AsyncResult for the task
        result = celery_app.AsyncResult(task_id)
        
        # Check the state
        if result.state == 'PENDING':
            response = {
                'task_id': task_id,
                'status': 'pending',
                'info': 'Task is waiting for execution'
            }
        elif result.state == 'STARTED':
            response = {
                'task_id': task_id,
                'status': 'started',
                'info': 'Task has been started'
            }
        elif result.state == 'SUCCESS':
            response = {
                'task_id': task_id,
                'status': 'completed',
                'result': result.get()
            }
        elif result.state == 'FAILURE':
            response = {
                'task_id': task_id,
                'status': 'failed',
                'error': str(result.result)
            }
        else:
            response = {
                'task_id': task_id,
                'status': result.state,
                'info': 'Unknown state'
            }
        
        return response
    except Exception as e:
        logger.error(f"Error checking task status for {task_id}: {str(e)}", exc_info=True)
        return {
            'task_id': task_id,
            'status': 'error',
            'error': str(e)
        }
