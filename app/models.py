from pydantic import BaseModel, HttpUrl, Field, model_validator, validator
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
import uuid
from enum import Enum
from sqlalchemy.ext.asyncio import AsyncSession
import tempfile

class RepoInfo(BaseModel):
    owner: str
    repo: str
    branch: Optional[str] = None
    # commit_sha: Optional[str] = None # Can be fetched

class RepoInputModel(BaseModel):
    repo_url: Optional[HttpUrl] = None
    repo_details: Optional[RepoInfo] = None

    @model_validator(mode='before')
    def check_either_url_or_details(cls, values):
        if bool(values.get('repo_url')) == bool(values.get('repo_details')):
            raise ValueError('Either repo_url or repo_details must be provided, but not both.')
        return values

class ComplianceCheckStatus(str, Enum):
    MET = "MET"
    NOT_MET = "NOT_MET"
    PARTIALLY_MET = "PARTIALLY_MET"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REQUIRES_REVIEW = "REQUIRES_REVIEW" # Indicates evidence found, needs human or LLM review
    NOT_EVIDENT = "NOT_EVIDENT" # Indicates no direct evidence found via initial scan
    ERROR_ANALYZING = "ERROR_ANALYZING"

class ComplianceChecklistItem(BaseModel):
    id: str = Field(..., description="Unique identifier for the compliance check, e.g., 'data_governance_accuracy'")
    criterion: str = Field(..., description="The specific compliance criterion being checked.")
    description: str = Field(..., description="Detailed description of the compliance requirement.")
    status: ComplianceCheckStatus = Field(default=ComplianceCheckStatus.NOT_EVIDENT, description="Status of the compliance check.")
    evidence: List[str] = Field(default_factory=list, description="Supporting evidence, e.g., file paths, code snippets, or LLM reasoning excerpts.")
    details: Optional[str] = Field(None, description="Further details or justification for the status.")
    llm_assessment_prompt: Optional[str] = Field(None, description="Prompt used if LLM assessment was performed.")
    relevant_risk_tiers: List['RiskTier'] = Field(default_factory=list, description="Risk tiers for which this check is most relevant.")

class ComplianceObligation(BaseModel):
    """
    Placeholder for ComplianceObligation.
    This was causing an ImportError in graph_nodes.py.
    TODO: Remove this and the import in graph_nodes.py once edit_file tool is fixed or the model is properly defined/removed.
    """
    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None

class CodeSignal(BaseModel):
    biometric: bool = False
    live_stream: bool = False # Renamed from liveStream, from realtime_stream_lib_detected
    uses_gpai: bool = False   # Renamed from usesGPAI, from gpai_lib_detected
    detected_libraries: List[str] = Field(default_factory=list) # From detected_libraries_summary

class CodeAnalysisResult(BaseModel):
    file_path: str # Path to the analyzed Python file
    imported_modules: List[str] = Field(default_factory=list) # List of top-level modules imported in this file
    # Potentially add other specific findings like function calls or class instantiations later

class CodeViolationDetail(BaseModel):
    file_path: str
    line_number: int
    module_name: Optional[str] = None # e.g., the imported module
    violating_code: Optional[str] = None # The actual line of code or relevant snippet
    policy_category: str # e.g., "biometric", "live_stream", "gpai", "sensitive_data"
    description: str # Brief description of why this is a violation

class GrepSignalItem(BaseModel):
    file_path: str
    line_number: int
    line_content: str

class RepositoryFile(BaseModel):
    path: str
    content: str
    file_type: str # e.g., 'markdown', 'openapi', 'python', 'javascript', 'typescript'
    language: Optional[str] = None # e.g., 'python', 'javascript'. More relevant for 'code' type.

class FuzzyMatchResult(BaseModel):
    obligation_id: str # ID of the EU AI Act obligation
    obligation_title: str # Title of the EU AI Act obligation
    repo_content_source: str # Identifier of the repo content (e.g., file path)
    repo_content_snippet: str # The actual snippet of text from the repo
    similarity_score: float
    # repo_content_embedding_id: Optional[str] = None 

class ComplianceMatch(BaseModel):
    """Represents a single compliance match found during analysis."""
    keyword: Optional[str] = None
    source_type: str  # 'documentation', 'code', 'code_analysis'
    source_content: Optional[str] = None
    source_index: Optional[int] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    line_content: Optional[str] = None
    obligation_id: Optional[str] = None
    obligation_title: Optional[str] = None
    confidence: float
    signal_type: Optional[str] = None
    reason: Optional[str] = None

class TierAnalysis(BaseModel):
    """Detailed analysis for a specific risk tier."""
    matches: List[ComplianceMatch] = Field(default_factory=list)
    score: float = 0
    
class ComplianceAnalysisDetails(BaseModel):
    """Detailed analysis of compliance across all risk tiers."""
    prohibited: TierAnalysis = Field(default_factory=TierAnalysis)
    high: TierAnalysis = Field(default_factory=TierAnalysis)
    limited: TierAnalysis = Field(default_factory=TierAnalysis)
    minimal: TierAnalysis = Field(default_factory=TierAnalysis)
    detected_keywords: List[str] = Field(default_factory=list)
    code_signals: List[ComplianceMatch] = Field(default_factory=list)
    documentation_signals: List[ComplianceMatch] = Field(default_factory=list)

class ScanResultModel(BaseModel):
    tier: str # e.g., 'prohibited', 'high', 'limited', 'minimal'
    checklist: List[ComplianceChecklistItem] # Updated from ChecklistItem
    doc_summary: Optional[List[str]] = Field(default_factory=list) # List of bullet points from LLM
    code_signals: Optional[CodeSignal] = None # Store the Pydantic model instance
    evidence_snippets: Optional[Dict[str, Any]] = Field(default_factory=dict) # Could be code snippets or doc parts
    repo_url: Optional[str] = None
    commit_sha: Optional[str] = None
    timestamp: Optional[datetime] = None
    grep_signals: Optional[List[GrepSignalItem]] = Field(default_factory=list)
    fuzzy_matches: List[FuzzyMatchResult] = Field(default_factory=list) # For vector-assisted classification results
    analysis_details: Optional[ComplianceAnalysisDetails] = None # Detailed compliance analysis

# Example of a more specific input model if we decide to enforce one or the other
class RepoUrlInput(BaseModel):
    repo_url: HttpUrl

class RepoDetailsInput(BaseModel):
    owner: str
    repo: str
    branch: Optional[str] = None

class ScanLogEntry(BaseModel):
    repo_url: HttpUrl # Or a field that uniquely identifies the scan, like a scan_id
    # repo_details: Optional[RepoInfo] = None # Could store this if repo_url is not canonical
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tier: str
    # Potentially a summary of checklist items or key findings
    # For now, let's keep it simple. Full result might be stored elsewhere or linked.

class ErrorResponse(BaseModel):
    error: str
    details: Optional[str] = None

class ScanInitiatedResponse(BaseModel):
    scan_id: str
    message: str
    websocket_url: str

# --- LangGraph State Model ---

class RiskTier(str, Enum):
    """Risk tier classification according to EU AI Act.
    
    Values are loaded from data/risk_tiers.yaml at runtime.
    """
    # These values must match the keys in risk_tiers.yaml
    PROHIBITED = "prohibited"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"
    UNKNOWN = "unknown" # For cases where classification fails or is pending
    
    @classmethod
    def get_description(cls, tier: str) -> str:
        """Get the description of a risk tier from the YAML configuration."""
        from app.utils.yaml_config import get_risk_tier_info
        return get_risk_tier_info(tier).get('description', 'No description available')
    
    @classmethod
    def get_examples(cls, tier: str) -> list:
        """Get examples of a risk tier from the YAML configuration."""
        from app.utils.yaml_config import get_risk_tier_info
        return get_risk_tier_info(tier).get('examples', [])
    
    @classmethod
    def get_legal_reference(cls, tier: str) -> str:
        """Get the legal reference of a risk tier from the YAML configuration."""
        from app.utils.yaml_config import get_risk_tier_info
        return get_risk_tier_info(tier).get('legal_reference', 'No legal reference available')
    
    @classmethod
    def get_compliance_deadline(cls, tier: str) -> str:
        """Get the compliance deadline of a risk tier from the YAML configuration."""
        from app.utils.yaml_config import get_risk_tier_info
        return get_risk_tier_info(tier).get('compliance_deadline', 'No deadline specified')

class APIScanResponse(BaseModel):
    """Model for the final JSON response of the graph scan API."""
    scan_id: Optional[str] = None # Added scan_id
    tier: Optional[RiskTier] = None
    checklist: Optional[List[ComplianceChecklistItem]] = Field(default_factory=list, description="Detailed compliance checklist results.")
    doc_summary: Optional[List[str]] = None
    detailed_code_violations: Optional[List[CodeViolationDetail]] = Field(default_factory=list)
    code_analysis_score: Optional[float] = None
    error_messages: Optional[List[str]] = None # Include errors in the response
    risk_classification_justification: Optional[str] = None # Added for LLM justification
    recommendations: Optional[List[str]] = Field(default_factory=list, description="Actionable recommendations based on the scan.")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="Timestamp of when the scan response was generated.")

class ScanCompletedMessage(BaseModel):
    """Model for the final WebSocket message when a scan is successfully completed."""
    scan_id: str
    event_type: str = "scan_completed"
    data: APIScanResponse

class ScanPersistenceData(BaseModel):
    """Model for data to be persisted to the database after a scan."""
    scan_id: uuid.UUID # Added
    user_id: Optional[str] = None # Added, to be populated by persist_scan_results_node
    status: Optional[str] = None # Added, e.g., "completed", "failed"
    
    repo_url: Optional[str] = None # From RepoInputModel or RepoInfo
    repo_owner: Optional[str] = None # From RepoInfo
    repo_name: Optional[str] = None # From RepoInfo
    commit_sha: Optional[str] = None # From ScanGraphState
    risk_tier: Optional[RiskTier] = None # From ScanGraphState
    checklist: Optional[List[ComplianceChecklistItem]] = None # Updated type
    doc_summary: Optional[List[str]] = None # For context, might be useful
    code_analysis_score: Optional[float] = None
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    error_messages: Optional[List[str]] = None # Errors encountered during the scan
    risk_classification_justification: Optional[str] = None # Added for LLM justification
    final_response_json: Optional[Dict[str, Any]] = None # Added to store the full API response

class ScanRecordResponse(BaseModel):
    """Response model for scan records retrieved from the database."""
    id: str
    repo_url: str
    repo_owner: Optional[str] = None
    repo_name: Optional[str] = None
    commit_sha: Optional[str] = None
    risk_tier: Optional[str] = None
    checklist: Optional[List[Dict[str, Any]]] = None
    doc_summary: Optional[List[str]] = None
    scan_timestamp: datetime
    error_messages: Optional[List[str]] = None
    
    class Config:
        from_attributes = True  # Allows the model to be created from SQLAlchemy models


class TaskSubmitResponse(BaseModel):
    """Response model for submitting an asynchronous scan task."""
    task_id: str
    status: str
    message: str
    repo_url: Optional[str] = None


class TaskStatusResponse(BaseModel):
    """Response model for checking the status of an asynchronous scan task."""
    task_id: str
    status: str  # pending, started, completed, failed
    info: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class ScanGraphState(BaseModel):
    """Manages the state of the repository scanning process graph."""
    scan_id: Optional[str] = None # Added scan_id to be available throughout the graph
    input_model: RepoInputModel
    repo_info: Optional[RepoInfo] = None
    commit_sha: Optional[str] = None
    temp_repo_path: Optional[str] = None
    repo_local_path: Optional[str] = None # Actual path to the cloned repository content
    _temp_dir_object: Optional[tempfile.TemporaryDirectory] = None # To manage temp dir lifecycle
    
    compliance_criteria: Optional[List[Dict[str, Any]]] = None # Added: Loaded compliance criteria
    discovered_files: Dict[str, List[str]] = Field(default_factory=dict) # e.g., {"markdown": [], "python": []}
    processed_docs_content: Dict[str, Any] = Field(default_factory=dict) # Added to store generic processed content
    file_content_cache: Dict[str, str] = Field(default_factory=dict) # path -> content
    
    # Processed documentation content
    extracted_markdown_docs: List[Dict[str, Any]] = Field(default_factory=list) # Changed from List[Tuple[str, str, List[str]]]
    parsed_openapi_specs: List[Tuple[str, Dict[str, Any]]] = Field(default_factory=list) # (path, parsed_content)
    data_governance_doc_findings: Optional[Dict[str, Any]] = None # Stores findings related to data governance documentation
    transparency_doc_findings: Optional[Dict[str, Any]] = None # Stores findings related to transparency documentation
    human_oversight_doc_findings: Optional[Dict[str, Any]] = None # Stores findings related to human oversight documentation
    
    doc_summary: Optional[List[str]] = None
    
    # Code analysis outputs
    # Stores CodeAnalysisResult per file path for detailed AST findings
    code_ast_analysis_results: Dict[str, CodeAnalysisResult] = Field(default_factory=dict) 
    ast_compliance_findings: Optional[Dict[str, List[Dict[str, Any]]]] = Field(default_factory=dict) # For specific compliance signals
    detailed_code_violations: List[CodeViolationDetail] = Field(default_factory=list)
    grep_search_results: List[Dict[str, Any]] = Field(default_factory=list) # Raw results from grep
    aggregated_code_signals: Optional[CodeSignal] = None # Combined signals from AST and grep
    code_analysis_score: Optional[float] = None
    code_complexity: Optional[Dict[str, Any]] = None # Added to store detailed cyclomatic complexity results

    # Risk Classification
    risk_tier: Optional[RiskTier] = None
    risk_classification_justification: Optional[str] = None # Added for LLM justification
    compliance_checklist: Optional[List[ComplianceChecklistItem]] = None # Updated type
    criterion_grep_results: Optional[Dict[str, List[Dict[str, Any]]]] = None # Added to store grep results for checklist generation

    # Data prepared for vector store
    repository_files_for_embedding: List[RepositoryFile] = Field(default_factory=list)
    
    # Status flags and intermediate results
    embedding_upsert_status: Dict[str, bool] = Field(default_factory=dict)
    fuzzy_matches: List[FuzzyMatchResult] = Field(default_factory=list)
    
    # Final output and operational tracking
    final_api_response: Optional[APIScanResponse] = None # This will be populated for the API
    persistence_data: Optional[ScanPersistenceData] = None # Data prepared for persistence
    persisted_record_id: Optional[uuid.UUID] = None # Add field for persisted record ID
    error_messages: List[str] = Field(default_factory=list) # Initialize as empty list
    current_node_name: Optional[str] = None # Tracks the current node being executed
    node_outputs: Dict[str, Any] = Field(default_factory=dict) # Stores outputs of each node for debugging/logging

    class Config:
        arbitrary_types_allowed = True
