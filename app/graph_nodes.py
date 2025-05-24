# app/graph_nodes.py

from typing import Dict, Any, Optional, List, Tuple, Set
from collections import defaultdict
from .models import (
    RepoInputModel, ScanGraphState, RepoInfo,
    CodeAnalysisResult, CodeSignal, RiskTier, APIScanResponse,
    ScanPersistenceData, CodeViolationDetail, ComplianceObligation, ComplianceChecklistItem,
    RepositoryFile, FuzzyMatchResult,
    # ComplianceStatus, # This was already here, good.
    ComplianceCheckStatus # Added this line
)
from .scanner import resolve_repo_input
import tempfile
import shutil
import os
import asyncio
import json
from pathlib import Path
from .utils import (
    get_repo_archive_info, download_repo_zip, unzip_archive,
    find_documentation_files, find_code_files,
    extract_text_and_headings_from_markdown, parse_openapi_file,
    fetch_github_repo_branch_info, read_file_content
)
from .config import settings
from .logger import get_logger
from .services.llm_service import LLMService 
from app.crud import create_scan_record, get_all_obligations_with_checklist_items, update_scan_record_with_results
from app.db.session import async_session_factory
from radon.complexity import cc_visit
from radon.raw import analyze as raw_analyze
import ast
import re
import subprocess
from datetime import datetime
import httpx
import zipfile
import io
from urllib.parse import urlparse
import inspect # Added import
import yaml
from pathlib import Path

logger_nodes = get_logger(__name__) 

# Path to the compliance criteria configuration file
COMPLIANCE_CRITERIA_PATH = Path(__file__).parent / "compliance_criteria.yaml"

def load_compliance_criteria() -> List[Dict[str, Any]]:
    """Loads compliance criteria from the YAML configuration file."""
    try:
        with open(COMPLIANCE_CRITERIA_PATH, 'r') as f:
            criteria_data = yaml.safe_load(f)
        
        # Convert relevant_risk_tiers strings to RiskTier enum members
        for criterion in criteria_data:
            if 'relevant_risk_tiers' in criterion and isinstance(criterion['relevant_risk_tiers'], list):
                criterion['relevant_risk_tiers'] = [
                    RiskTier[tier_str.upper()] for tier_str in criterion['relevant_risk_tiers']
                    if tier_str.upper() in RiskTier.__members__
                ]
            else:
                # Default to all risk tiers if not specified or malformed, or handle as an error
                criterion['relevant_risk_tiers'] = list(RiskTier)
                logger_nodes.warning(
                    f"Risk tiers for criterion '{criterion.get('id', 'Unknown')}' are missing, malformed, or not a list. Defaulting to all tiers."
                )
        return criteria_data
    except FileNotFoundError:
        logger_nodes.error(f"Compliance criteria file not found at {COMPLIANCE_CRITERIA_PATH}. Returning empty criteria list.")
        return []
    except yaml.YAMLError as e:
        logger_nodes.error(f"Error parsing compliance criteria YAML file: {e}. Returning empty criteria list.")
        return []
    except KeyError as e:
        logger_nodes.error(f"Invalid RiskTier string in compliance_criteria.yaml: {e}. Please check the 'relevant_risk_tiers' values.")
        return [] # Or raise an error / return partially loaded if appropriate
    except Exception as e:
        logger_nodes.error(f"An unexpected error occurred while loading compliance criteria: {e}. Returning empty criteria list.")
        return []

# INITIAL_COMPLIANCE_CRITERIA is now loaded from the YAML file
# This variable will be populated by calling load_compliance_criteria()
# We can load it once when the module is imported, or within the node itself.
# For simplicity in a graph context where nodes might re-initialize, loading it inside the node or 
# ensuring it's loaded globally once and available is key.
# Let's load it globally for now for simplicity, assuming this module is imported once.
INITIAL_COMPLIANCE_CRITERIA = load_compliance_criteria()

# --- Sensitive Library Definitions for AST Analysis ---
SENSITIVE_LIBRARIES_CONFIG = {
    "biometric": ["face_recognition", "cv2", "dlib", "mediapipe"], 
    "live_stream": ["websockets", "socketio", "aiohttp", "kafka", "pika", "rtsp", "webrtc"], 
    "gpai": ["transformers", "tensorflow", "torch", "keras", "openai", "anthropic", "langchain", "google.generativeai"]
}

_ALL_SENSITIVE_IMPORTS_SET = set()
for category, libs in SENSITIVE_LIBRARIES_CONFIG.items():
    for lib in libs:
        if lib == "cv2": 
            _ALL_SENSITIVE_IMPORTS_SET.add("opencv-python") 
            _ALL_SENSITIVE_IMPORTS_SET.add("cv2") 
        else:
            _ALL_SENSITIVE_IMPORTS_SET.add(lib)
ALL_SENSITIVE_IMPORTS = list(_ALL_SENSITIVE_IMPORTS_SET) 

COMPLIANCE_LIBRARIES_CONFIG: Dict[str, Set[str]] = {
    "data_handling": {"sqlite3", "sqlalchemy", "psycopg2", "pymysql", "pandas", "csv", "json", "pickle"},
    "logging": {"logging"},
    "network": {"requests", "httpx", "aiohttp", "urllib", "socket"} 
}

# --- End Sensitive Library Definitions ---

async def initial_setup_node(state: ScanGraphState) -> dict:
    """Initial setup node for the scan graph."""
    logger_nodes.info("--- Executing InitialSetupNode ---")
    # This node would typically initialize things, validate input, etc.
    # For now, it's a placeholder.
    if not state.scan_id or not state.input_model:
        error_msg = "Scan ID or Input Model not found in initial state."
        logger_nodes.error(error_msg)
        return {"error_messages": state.error_messages + [error_msg]}

    logger_nodes.info(f"Initial setup for scan_id: {state.scan_id} with input: {state.input_model.repo_url}")
    return {
        "repo_url": state.input_model.repo_url, # Pass along essential info
        "error_messages": list(state.error_messages) # Ensure error_messages is initialized
    }

class PythonAstAnalyzer(ast.NodeVisitor):
    """Visits AST nodes to find imported modules and identify sensitive library usage and compliance signals."""
    def __init__(self, file_path: str, file_content: str):
        self.file_path = file_path
        self.file_lines = file_content.splitlines()
        self.violations: List[CodeViolationDetail] = []
        self._reported_violation_keys = set()
        self.compliance_signals: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def _add_violation(self, module_root: str, node: ast.AST, policy_category: str, description: str):
        violation_key = (module_root, node.lineno, policy_category)
        if violation_key in self._reported_violation_keys:
            return
            
        line_content = self.file_lines[node.lineno - 1].strip() if 0 < node.lineno <= len(self.file_lines) else "N/A (line out of bounds)"
        
        violation = CodeViolationDetail(
            file_path=self.file_path,
            line_number=node.lineno,
            module_name=module_root, 
            violating_code=line_content,
            policy_category=policy_category,
            description=description
        )
        self.violations.append(violation)
        self._reported_violation_keys.add(violation_key)

    def _check_and_report_module(self, module_name_full: str, node: ast.AST):
        module_root = module_name_full.split('.')[0]
        module_to_check_in_config = "opencv-python" if module_root == "cv2" else module_root
        modules_to_evaluate = {module_root, module_to_check_in_config}

        for eval_module in modules_to_evaluate:
            for category, modules_in_category in SENSITIVE_LIBRARIES_CONFIG.items():
                if eval_module in modules_in_category:
                    description = f"Import of sensitive module '{module_root}' (via '{module_name_full}') linked to '{category}' policy."
                    self._add_violation(module_root, node, category, description)

        for compliance_category, libraries in COMPLIANCE_LIBRARIES_CONFIG.items():
            if module_root in libraries:
                signal_detail = {
                    "file": self.file_path,
                    "line": node.lineno,
                    "library": module_root,
                    "original_import": module_name_full
                }
                self.compliance_signals[compliance_category].append(signal_detail)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._check_and_report_module(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._check_and_report_module(node.module, node)
        self.generic_visit(node)

    def get_violations(self) -> List[CodeViolationDetail]:
        return self.violations

    def get_compliance_signals(self) -> Dict[str, List[Dict[str, Any]]]:
        return dict(self.compliance_signals)

def _analyze_single_python_file(py_file_path: str, repo_base_path: str) -> Tuple[str, List[CodeViolationDetail], Dict[str, List[Dict[str, Any]]], Optional[str]]:
    """
    Synchronous helper to analyze a single Python file. 
    Returns (file_path, list_of_code_violation_details, compliance_signals, error_message).
    """
    error_message = None
    violations = []
    compliance_signals = defaultdict(list)
    full_py_file_path = os.path.join(repo_base_path, py_file_path)

    try:
        # Ensure the path is absolute and exists before trying to open
        if not os.path.exists(full_py_file_path):
            logger_nodes.error(f"File not found at constructed path: {full_py_file_path} (original relative: {py_file_path})")
            return py_file_path, [], {}, f"File not found: {full_py_file_path}"

        with open(full_py_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        tree = ast.parse(content, filename=py_file_path) # filename for ast can be relative for error reporting
        analyzer = PythonAstAnalyzer(file_path=py_file_path, file_content=content) # Pass relative path for reporting
        analyzer.visit(tree)
        violations_in_file = analyzer.get_violations()
        compliance_signals_in_file = analyzer.get_compliance_signals()
        
        if violations_in_file:
            logger_nodes.debug(f"Found {len(violations_in_file)} violations in: {py_file_path}")
            
        return py_file_path, violations_in_file, compliance_signals_in_file, None
    except SyntaxError as e_syn:
        error_msg = f"SyntaxError analyzing {py_file_path}: {e_syn}"
        logger_nodes.warning(error_msg)
        return py_file_path, [], {}, error_msg
    except Exception as e:
        error_msg = f"Error analyzing Python file {py_file_path}: {e}"
        logger_nodes.error(f"{error_msg} - in _analyze_single_python_file", exc_info=True)
        return py_file_path, [], {}, error_msg

async def analyze_python_code_node(state: ScanGraphState) -> dict:
    """Analyzes discovered Python files using AST to find imports and identify sensitive library usage and compliance signals."""
    logger_nodes.info("--- Executing AnalyzePythonCodeNode ---")
    all_detailed_violations: List[CodeViolationDetail] = []
    ast_compliance_findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    error_messages = list(state.error_messages) 

    python_files = state.discovered_files.get('python_files', [])
    if not python_files:
        logger_nodes.info("No Python files to analyze.")
        return {
            "detailed_code_violations": all_detailed_violations,
            "ast_compliance_findings": dict(ast_compliance_findings),
            "error_messages": error_messages
        }

    logger_nodes.info(f"Analyzing {len(python_files)} Python files for detailed violations and compliance signals...")
    
    thread_results = await asyncio.gather(*[asyncio.to_thread(_analyze_single_python_file, fp, state.repo_local_path) for fp in python_files])

    for file_path, file_violations, file_compliance_signals, error_msg in thread_results:
        if error_msg:
            error_messages.append(error_msg)
        all_detailed_violations.extend(file_violations)
        if file_compliance_signals:
            for category, signals_list in file_compliance_signals.items():
                if signals_list:
                    ast_compliance_findings[category].extend(signals_list)
        
    logger_nodes.info(f"Python code analysis complete. Found {len(all_detailed_violations)} detailed violations. Compliance signals detected: { {k: len(v) for k, v in ast_compliance_findings.items()} }")

    return {
        "detailed_code_violations": all_detailed_violations,
        "ast_compliance_findings": dict(ast_compliance_findings),
        "error_messages": error_messages
    }

def _analyze_single_file_complexity(absolute_file_path: str, relative_file_path: str) -> Tuple[str, float, Optional[Dict[str, Any]], Optional[str]]:
    """Analyzes a single Python file for code complexity metrics."""
    try:
        if not os.path.exists(absolute_file_path):
            err_msg = f"File not found at constructed path: {absolute_file_path} (original relative: {relative_file_path})"
            logger_nodes.error(err_msg)
            return relative_file_path, 0.0, None, err_msg

        with open(absolute_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        raw_metrics = raw_analyze(content)
        complexity_blocks_radon = cc_visit(content)

        current_file_total_complexity = 0.0
        block_details_for_file = []
        if complexity_blocks_radon:
            current_file_total_complexity = sum(b.complexity for b in complexity_blocks_radon)
            for block in complexity_blocks_radon:
                block_details_for_file.append({
                    "name": getattr(block, 'name', 'N/A'),
                    "type": str(getattr(block, 'type', 'N/A')),
                    "lineno": getattr(block, 'lineno', 0),
                    "col_offset": getattr(block, 'col_offset', 0),
                    "endline": getattr(block, 'endline', 0),
                    "complexity": getattr(block, 'complexity', 0),
                })
        
        analysis_details = {
            "complexity_blocks": block_details_for_file,
            "raw_analysis": raw_metrics._asdict() if raw_metrics else {}
        }
        return relative_file_path, current_file_total_complexity, analysis_details, None

    except Exception as e:
        err_msg = f"Error analyzing file {relative_file_path} for complexity: {e}"
        logger_nodes.error(err_msg, exc_info=True)
        return relative_file_path, 0.0, None, err_msg

async def analyze_code_complexity_node(state: ScanGraphState) -> dict:
    """Analyzes discovered Python files for code complexity metrics using concurrent processing."""
    logger_nodes.info("--- Executing AnalyzeCodeComplexityNode ---")
    local_error_messages = list(state.error_messages) # Initialize with existing errors
    files_processed_successfully = 0
    code_ast_analysis_results: Dict[str, Any] = {}

    python_files_relative_paths = state.discovered_files.get("python_files", [])

    if not python_files_relative_paths:
        logger_nodes.info("No Python files found to analyze for complexity.")
        # Return structure consistent with successful run but no files
        return {
            "code_complexity": {
                "average_complexity": 0,
                "details_per_file": {}
            },
            "error_messages": local_error_messages
        }
    else:
        logger_nodes.info(f"Analyzing {len(python_files_relative_paths)} Python files for complexity...")

    repo_local_path = state.repo_local_path
    if not repo_local_path or not os.path.isdir(repo_local_path):
        error_msg = f"Invalid or missing repo_local_path: {repo_local_path}"
        logger_nodes.error(error_msg)
        local_error_messages.append(error_msg)
        return {
            "code_complexity": None, # Indicates a fundamental issue like missing repo path
            "error_messages": local_error_messages
        }

    cumulative_complexity = 0.0
    tasks = []
    for relative_file_path in python_files_relative_paths:
        absolute_file_path = os.path.join(repo_local_path, relative_file_path)
        tasks.append(asyncio.to_thread(_analyze_single_file_complexity, absolute_file_path, relative_file_path))

    thread_results = await asyncio.gather(*tasks)

    for rel_path, file_complexity, analysis_details, error_msg in thread_results:
        if error_msg:
            local_error_messages.append(error_msg)
        if analysis_details is not None: # Successfully analyzed
            code_ast_analysis_results[rel_path] = analysis_details
            cumulative_complexity += file_complexity
            files_processed_successfully += 1
    
    avg_complexity = 0.0
    if files_processed_successfully > 0:
        avg_complexity = cumulative_complexity / files_processed_successfully

    output_code_complexity_dict = {
        "average_complexity": avg_complexity,
        "details_per_file": code_ast_analysis_results
    }

    return {
        "code_complexity": output_code_complexity_dict,
        "error_messages": local_error_messages
    }

async def download_and_unzip_repo_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing download_and_unzip_repo_node ---")
    input_model = state.input_model
    repo_local_path = None
    error_messages = list(state.error_messages)
    temp_dir_obj = None # To hold the TemporaryDirectory object

    try:
        owner, repo_name, branch, repo_url_str = None, None, None, None

        if input_model.repo_url:
            repo_url_str = str(input_model.repo_url)
            parsed_url = urlparse(repo_url_str)
            path_parts = parsed_url.path.strip('/').split('/')
            if len(path_parts) >= 2 and parsed_url.hostname == "github.com":
                owner = path_parts[0]
                repo_name = path_parts[1].replace('.git', '')
                # Branch might be part of the URL (e.g., /tree/branch_name) or default
                if len(path_parts) > 3 and path_parts[2] == 'tree':
                    branch = path_parts[3]
                else:
                    # Attempt to fetch default branch if not specified
                    # This requires an API call, deferring for now or assuming 'main'/'master'
                    # For simplicity, we'll try common defaults or require explicit branch for non-URL inputs
                    pass # Branch remains None, will be handled by get_repo_archive_info
            else:
                error_messages.append(f"Invalid GitHub URL format: {repo_url_str}")
                logger_nodes.error(f"Invalid GitHub URL format: {repo_url_str}")
                return {"repo_local_path": None, "error_messages": error_messages, "_temp_dir_object": None}

        elif input_model.repo_details:
            owner = input_model.repo_details.owner
            repo_name = input_model.repo_details.repo
            branch = input_model.repo_details.branch
            repo_url_str = f"https://github.com/{owner}/{repo_name}"
            if branch:
                repo_url_str += f"/tree/{branch}"
        else:
            error_messages.append("No repository input provided.")
            logger_nodes.error("No repository input provided in input_model.")
            return {"repo_local_path": None, "error_messages": error_messages, "_temp_dir_object": None}

        if not owner or not repo_name:
            error_messages.append("Could not determine repository owner and name.")
            logger_nodes.error("Could not determine repository owner and name.")
            return {"repo_local_path": None, "error_messages": error_messages, "_temp_dir_object": None}

        # Create RepoInfo object for the utility function
        repo_info_for_util = RepoInfo(owner=owner, repo=repo_name, branch=branch) # branch can be None

        # --- BEGIN DIAGNOSTIC LOGGING ---
        logger_nodes.info(f"Attempting to call get_repo_archive_info: {get_repo_archive_info}")
        try:
            logger_nodes.info(f"Inspect get_repo_archive_info args: {inspect.getfullargspec(get_repo_archive_info)}")
        except Exception as e:
            logger_nodes.error(f"Could not inspect get_repo_archive_info: {e}")
        try:
            logger_nodes.info(f"Source file of get_repo_archive_info: {inspect.getfile(get_repo_archive_info)}")
        except TypeError:
            logger_nodes.warning("Could not determine source file for get_repo_archive_info (likely a built-in or C module).")
        # --- END DIAGNOSTIC LOGGING ---
        
        # Use a helper to get archive URL and potentially default branch if not specified
        # get_repo_archive_info will handle None branch and find default
        archive_url, actual_branch, commit_sha = await get_repo_archive_info(repo_details_obj=repo_info_for_util, token=settings.GITHUB_TOKEN)
        
        # Update state with the definitive repo_info (especially if default branch was resolved)
        # and the commit_sha
        state.repo_info = RepoInfo(owner=owner, repo=repo_name, branch=actual_branch) # This is already done by the caller or should be set here
        state.commit_sha = commit_sha

        logger_nodes.info(f"Attempting to download {owner}/{repo_name} (Branch: {actual_branch}, SHA: {commit_sha}) from: {archive_url}")

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            headers = {}
            if settings.GITHUB_TOKEN:
                headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"
            
            response = await client.get(archive_url, headers=headers)
            response.raise_for_status() # Raises HTTPStatusError for 4xx/5xx responses

            # Create a persistent temporary directory
            # The directory will be cleaned up when temp_dir_obj is garbage collected or explicitly cleaned.
            # For LangGraph, if state is passed around, this object needs to be managed carefully.
            # Storing the path string in repo_local_path is standard.
            temp_dir_obj = tempfile.TemporaryDirectory()
            repo_local_path = temp_dir_obj.name
            logger_nodes.info(f"Created temporary directory: {repo_local_path}")

            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                # GitHub zips usually have a single top-level directory like 'reponame-branchname'
                # We want to extract the contents of this directory directly into our temp_dir_obj.name
                
                # Get list of all files and directories in zip
                members = zf.namelist()
                if not members:
                    raise ValueError("ZIP archive is empty.")

                # Determine the root directory name within the zip (e.g., 'myrepo-main/')
                # It's typically the first member if it's a directory
                zip_root_dir = ""
                common_prefix = os.path.commonprefix(members)
                if common_prefix and zf.getinfo(common_prefix).is_dir():
                    zip_root_dir = common_prefix
                
                logger_nodes.info(f"Zip root directory identified as: '{zip_root_dir}'. Extracting contents.")

                for member_info in zf.infolist():
                    # Skip __MACOSX or other unwanted meta-files if any
                    if member_info.filename.startswith('__MACOSX/'):
                        continue
                    
                    # Adjust path to extract files directly into repo_local_path
                    # by stripping the zip_root_dir prefix
                    if zip_root_dir and member_info.filename.startswith(zip_root_dir):
                        target_path = os.path.join(repo_local_path, member_info.filename[len(zip_root_dir):])
                    else:
                        # If no common root, or file is not under it (should not happen for GitHub zips)
                        target_path = os.path.join(repo_local_path, member_info.filename)
                    
                    # Ensure target_path is within repo_local_path to prevent Zip Slip vulnerability
                    if not os.path.abspath(target_path).startswith(os.path.abspath(repo_local_path)):
                        raise zipfile.BadZipFile(f"Attempted Zip Slip vulnerability: {member_info.filename}")

                    if member_info.is_dir():
                        os.makedirs(target_path, exist_ok=True)
                    else:
                        # Create parent directory if it doesn't exist
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        with open(target_path, "wb") as f_out:
                            f_out.write(zf.read(member_info.filename))
                
            logger_nodes.info(f"Successfully downloaded and unzipped repository to {repo_local_path}")

    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP error occurred while downloading repository: {e.request.url} - {e.response.status_code} - {e.response.text[:200]}"
        logger_nodes.error(error_msg)
        error_messages.append(error_msg)
        if temp_dir_obj: temp_dir_obj.cleanup()
        temp_dir_obj = None
        repo_local_path = None
    except httpx.RequestError as e:
        error_msg = f"Request error occurred while downloading repository: {e.request.url} - {e}"
        logger_nodes.error(error_msg)
        error_messages.append(error_msg)
        if temp_dir_obj: temp_dir_obj.cleanup()
        temp_dir_obj = None
        repo_local_path = None
    except zipfile.BadZipFile as e:
        error_msg = f"Error unzipping repository: Bad ZIP file. {e}"
        logger_nodes.error(error_msg)
        error_messages.append(error_msg)
        if temp_dir_obj: temp_dir_obj.cleanup()
        temp_dir_obj = None
        repo_local_path = None
    except ValueError as e:
        error_msg = f"Error processing repository: {e}"
        logger_nodes.error(error_msg)
        error_messages.append(error_msg)
        if temp_dir_obj: temp_dir_obj.cleanup()
        temp_dir_obj = None
        repo_local_path = None
    except Exception as e:
        error_msg = f"An unexpected error occurred in download_and_unzip_repo_node: {type(e).__name__} - {e}"
        logger_nodes.error(error_msg, exc_info=True)
        error_messages.append(error_msg)
        if temp_dir_obj: temp_dir_obj.cleanup()
        temp_dir_obj = None
        repo_local_path = None

    # The temp_dir_obj needs to be kept alive for the duration of the scan.
    # Storing it in the state dict directly. Pydantic might complain if it's not serializable.
    # A better approach for long-lived temp dirs might be needed if state is serialized.
    # For now, we return it, and the graph orchestrator might need to manage its lifecycle.
    # Or, we simply rely on it staying in scope of this Python process.
    # Let's try returning it in the dict and see how LangGraph handles it or if we need to adjust.
    # If Pydantic has issues, we'll remove it from the return and just pass the path.
    # The `tempfile.TemporaryDirectory` object should be stored in `state.temp_dir_obj` (new field)
    # or managed by the orchestrator if it needs to survive beyond this node's scope in a complex way.
    # For now, we are not adding it to the state model to avoid Pydantic serialization issues with non-serializable objects.
    # The temporary directory will be cleaned up when `temp_dir_obj` goes out of scope and is garbage collected.
    # This is usually fine if the entire scan happens within one continuous process flow.

    # We will add 'temp_dir_obj_ref' to ScanGraphState if we want to manage its lifecycle explicitly via state.
    # For now, we are not adding it to the state model to avoid Pydantic serialization issues with non-serializable objects.
    # The temporary directory will be cleaned up when `temp_dir_obj` goes out of scope and is garbage collected.
    # This is usually fine if the entire scan happens within one continuous process flow.

    return {
        "repo_local_path": repo_local_path, 
        "error_messages": error_messages,
        "repo_info": state.repo_info, # Pass along updated repo_info
        "commit_sha": state.commit_sha, # Pass along commit_sha
        "_temp_dir_object": temp_dir_obj # Return the TemporaryDirectory object itself
    }

async def discover_files_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing discover_files_node ---")
    repo_path = state.repo_local_path
    discovered_files_map: Dict[str, List[str]] = defaultdict(list)
    error_messages = list(state.error_messages)

    if not repo_path or not os.path.isdir(repo_path):
        error_msg = f"Repository path '{repo_path}' is invalid or not a directory."
        logger_nodes.error(error_msg)
        error_messages.append(error_msg)
        return {"discovered_files": {}, "error_messages": error_messages}

    logger_nodes.info(f"Discovering files in repository: {repo_path}")

    # Define file types and their corresponding keys in discovered_files_map
    # Keys should align with what downstream nodes expect, e.g., 'python_files', 'markdown_files'
    file_type_map = {
        '.md': 'markdown_files',
        '.py': 'python_files',
        '.json': 'openapi_files', # Potential OpenAPI/JSON files
        '.yaml': 'openapi_files', # Potential OpenAPI/YAML files
        '.yml': 'openapi_files',  # Potential OpenAPI/YAML files
        '.js': 'javascript_files',
        '.ts': 'typescript_files',
        # Add other relevant file types here, e.g., for requirements, Dockerfile, etc.
        'requirements.txt': 'requirements_files', # Specific file name
        'Dockerfile': 'docker_files' # Specific file name
    }
    # Files to ignore by name or pattern
    ignore_patterns = ['.git', '__pycache__', 'node_modules', '.DS_Store', 'venv', '.env']
    # Directories to ignore completely
    ignore_dirs = ['.git', '__pycache__', 'node_modules', 'venv', 'dist', 'build', 'docs/build'] 

    try:
        for root, dirs, files in os.walk(repo_path, topdown=True):
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if d not in ignore_dirs and not any(d.startswith(p) for p in ignore_patterns)]
            
            for file_name in files:
                if any(file_name.startswith(p) for p in ignore_patterns) or any(p in file_name for p in ignore_patterns if '*' in p ):
                    continue # Skip ignored files

                file_path = os.path.join(root, file_name)
                relative_path = os.path.relpath(file_path, repo_path)

                # Check for specific file names first
                matched_specific_file = False
                for specific_name, key_name in file_type_map.items():
                    if file_name == specific_name:
                        discovered_files_map[key_name].append(relative_path)
                        logger_nodes.debug(f"Discovered {key_name.replace('_files', '')} file: {relative_path}")
                        matched_specific_file = True
                        break
                if matched_specific_file:
                    continue

                # Then check by extension
                _, ext = os.path.splitext(file_name)
                if ext:
                    ext_lower = ext.lower()
                    if ext_lower in file_type_map:
                        key_name = file_type_map[ext_lower]
                        discovered_files_map[key_name].append(relative_path)
                        logger_nodes.debug(f"Discovered {key_name.replace('_files', '')} file ({ext_lower}): {relative_path}")
                    # else:
                        # logger_nodes.debug(f"Skipping file with unmapped extension '{ext_lower}': {relative_path}")
            
    except Exception as e:
        error_msg = f"Error during file discovery in {repo_path}: {e}"
        logger_nodes.error(error_msg, exc_info=True)
        error_messages.append(error_msg)
        # Return empty or partially discovered files if error occurs mid-way?
        # For now, returning what was found before the error.

    # Convert defaultdict to dict for the state
    final_discovered_files = dict(discovered_files_map)
    logger_nodes.info(f"File discovery completed. Found: { {k: len(v) for k, v in final_discovered_files.items()} }")

    return {
        "discovered_files": final_discovered_files,
        "error_messages": error_messages
    }

from app.utils import extract_text_and_headings_from_markdown, parse_openapi_file # Add necessary imports

async def process_discovered_files_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing process_discovered_files_node ---")
    repo_path = state.repo_local_path
    discovered_files_map = state.discovered_files
    error_messages = list(state.error_messages)

    # Initialize or copy existing state fields to update
    file_content_cache: Dict[str, str] = state.file_content_cache.copy() if state.file_content_cache else {}
    extracted_markdown_docs: List[Dict[str, Any]] = list(state.extracted_markdown_docs) if state.extracted_markdown_docs else []
    parsed_openapi_specs: List[Tuple[str, Dict[str, Any]]] = list(state.parsed_openapi_specs) if state.parsed_openapi_specs else []

    if not repo_path or not os.path.isdir(repo_path):
        error_msg = f"Repository path '{repo_path}' is invalid or not a directory for processing files."
        logger_nodes.error(error_msg)
        error_messages.append(error_msg)
        return {
            "file_content_cache": file_content_cache,
            "extracted_markdown_docs": extracted_markdown_docs,
            "parsed_openapi_specs": parsed_openapi_specs,
            "error_messages": error_messages
        }

    logger_nodes.info(f"Processing discovered files from: {repo_path}")
    files_processed_count = 0

    for file_category, relative_paths in discovered_files_map.items():
        logger_nodes.info(f"Processing {len(relative_paths)} files in category: {file_category}")
        for rel_path in relative_paths:
            abs_file_path = os.path.join(repo_path, rel_path)
            if not os.path.isfile(abs_file_path):
                warn_msg = f"File not found at {abs_file_path} (relative: {rel_path}), skipping."
                logger_nodes.warning(warn_msg)
                # error_messages.append(warn_msg) # Decide if this should be a hard error
                continue
            
            try:
                with open(abs_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                file_content_cache[rel_path] = content
                files_processed_count += 1
                logger_nodes.debug(f"Cached content for: {rel_path} ({len(content)} bytes)")

                # Specific processing based on category
                if file_category == 'markdown_files':
                    try:
                        text_content, headings = extract_text_and_headings_from_markdown(abs_file_path)
                        if text_content:
                            extracted_markdown_docs.append({
                                "file_path": rel_path, 
                                "content": text_content, 
                                "headings": headings
                            })
                            logger_nodes.debug(f"Extracted Markdown from: {rel_path}")
                    except Exception as md_e:
                        error_msg = f"Error extracting markdown from {rel_path}: {md_e}"
                        logger_nodes.error(error_msg, exc_info=True)
                        error_messages.append(error_msg)

                elif file_category == 'openapi_files': # Covers .json, .yaml, .yml from discover_node
                    try:
                        parsed_spec = parse_openapi_file(abs_file_path)
                        if parsed_spec: # parse_openapi_file returns None if not a valid spec
                            parsed_openapi_specs.append((rel_path, parsed_spec))
                            logger_nodes.debug(f"Parsed OpenAPI/Swagger spec from: {rel_path}")
                        # else:
                            # logger_nodes.debug(f"File {rel_path} was not a recognized OpenAPI/Swagger spec.")
                    except Exception as oapi_e:
                        error_msg = f"Error parsing OpenAPI/Swagger file {rel_path}: {oapi_e}"
                        logger_nodes.error(error_msg, exc_info=True)
                        error_messages.append(error_msg)
                
                # Other categories like 'python_files', 'javascript_files' are just cached for now.
                # Specific parsing for them will happen in downstream nodes.

            except Exception as e:
                error_msg = f"Error processing file {rel_path}: {e}"
                logger_nodes.error(error_msg, exc_info=True)
                error_messages.append(error_msg)

    logger_nodes.info(f"File processing completed. Total files cached: {files_processed_count}. Markdown docs: {len(extracted_markdown_docs)}. OpenAPI specs: {len(parsed_openapi_specs)}.")

    return {
        "file_content_cache": file_content_cache,
        "extracted_markdown_docs": extracted_markdown_docs,
        "parsed_openapi_specs": parsed_openapi_specs,
        "error_messages": error_messages
    }

from app.config import settings
from langchain_openai.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser # For RunnableSequence
from langchain_core.runnables import RunnableSequence # Explicit import for clarity

async def _summarize_single_doc_content(file_path: str, content: str, llm_chain: RunnableSequence) -> Tuple[str, Optional[str], Optional[str]]:
    """Helper function to summarize a single document's content using the provided LLM chain."""
    if not content.strip():
        logger_nodes.info(f"Skipping summarization for empty document: {file_path}")
        return file_path, None, f"Skipped summarization for empty document: {file_path}"
    
    max_chars = 25000 # Adjusted based on typical context limits and token counts
    if len(content) > max_chars:
        content = content[:max_chars]
        logger_nodes.warning(f"Content for {file_path} was truncated to {max_chars} characters for summarization.")

    try:
        # Ensure the input to ainvoke is a dictionary matching the prompt's input_variables
        logger_nodes.debug(f"Summarizing content for {file_path}...")
        # summary = await summarization_chain.ainvoke(document_content=content) # Old incorrect call
        summary = await llm_chain.ainvoke({"document_content": content}) # Corrected call
        logger_nodes.info(f"Successfully summarized {file_path}")
        return file_path, summary, None
    except Exception as e:
        error_msg = f"Error summarizing document {file_path}: {e}"
        logger_nodes.error(error_msg, exc_info=True) # Log with traceback
        return file_path, None, error_msg


async def summarize_documentation_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing summarize_documentation_node ---")
    local_error_messages = list(state.error_messages)
    per_file_summaries: Dict[str, str] = {}

    if not settings.OPENAI_API_KEY:
        error_msg = "OpenAI API key not configured. Skipping documentation summarization."
        logger_nodes.error(error_msg)
        local_error_messages.append(error_msg)
        return {
            "documentation_summary": {
                "overall_summary": "Skipped due to missing OpenAI API key.",
                "per_file_summaries": {}
            },
            "error_messages": local_error_messages
        }

    markdown_docs = state.extracted_markdown_docs
    if not markdown_docs:
        logger_nodes.info("No Markdown documents found to summarize.")
        return {
            "documentation_summary": {
                "overall_summary": "No Markdown documents found.",
                "per_file_summaries": {}
            },
            "error_messages": local_error_messages
        }

    logger_nodes.info(f"Summarizing {len(markdown_docs)} Markdown documents...")

    try:
        llm = ChatOpenAI(temperature=0, openai_api_key=settings.OPENAI_API_KEY, model_name="gpt-3.5-turbo")
        prompt_template = PromptTemplate(
            input_variables=["document_content"],
            template=(
                "Summarize the following documentation content. Focus on the key purposes, functionalities, "
                "and any compliance-related information (like data handling, security, user rights, or model limitations) mentioned. "
                "Provide a concise summary (2-4 paragraphs if possible) of the core information presented in the document.\n\n"
                "DOCUMENT CONTENT:\n"
                "{document_content}\n\n"
                "CONCISE SUMMARY:"
            )
        )
        # For older Langchain versions, LLMChain is used. For newer, it's `prompt | llm | parser`.
        # Assuming LLMChain for now based on typical project structure unless specified.
        summarization_chain = prompt_template | llm | StrOutputParser()
    except Exception as e:
        error_msg = f"Failed to initialize LLM for summarization: {e}"
        logger_nodes.error(error_msg, exc_info=True)
        local_error_messages.append(error_msg)
        return {
            "documentation_summary": {
                "overall_summary": "Failed to initialize summarization model.",
                "per_file_summaries": {}
            },
            "error_messages": local_error_messages
        }

    tasks = []
    for doc_info in markdown_docs:
        file_path = doc_info.get("file_path", "Unknown_file")
        content = doc_info.get("content", "")
        # Pass the created chain to the helper
        tasks.append(_summarize_single_doc_content(file_path, content, summarization_chain))

    summarization_results = await asyncio.gather(*tasks)

    for file_path, summary, error_msg in summarization_results:
        if error_msg:
            local_error_messages.append(error_msg)
        if summary:
            per_file_summaries[file_path] = summary
    
    overall_summary_text = f"Summarized {len(per_file_summaries)} out of {len(markdown_docs)} documents."
    if not per_file_summaries and markdown_docs:
        overall_summary_text = "Could not generate summaries for any document."
    elif not markdown_docs:
        overall_summary_text = "No documents to summarize."

    return {
        "documentation_summary": {
            "overall_summary": overall_summary_text,
            "per_file_summaries": per_file_summaries
        },
        "error_messages": local_error_messages
    }


async def classify_risk_tier_node(state: ScanGraphState) -> dict:
    """
    Classifies the AI system's risk tier based on summarized documentation and EU AI Act criteria using an LLM.
    """
    logger_nodes.info("Starting risk tier classification...")

    if not state.doc_summary:
        logger_nodes.warning("No documentation summary available to classify risk tier. Defaulting to UNKNOWN.")
        # Even if no docs, we might still want to run LLM if other signals exist, or have a default path.
        # For now, let's assume docs are primary for this node.
        # If we want to proceed without docs, this logic needs adjustment.
        return {
            "risk_tier": RiskTier.UNKNOWN, 
            "risk_classification_justification": "Risk tier not assessed due to missing documentation summary.",
            "error_messages": list(state.error_messages)
        }

    # Combine summaries into a single text for the LLM prompt
    # combined_summary_text = "\n".join(summarized_docs.get("per_file_summaries", {}).values())
    # Using overall_summary as it's more concise and already an aggregation
    combined_summary_text = state.doc_summary.get("overall_summary", "")
    if not combined_summary_text.strip() and state.doc_summary.get("per_file_summaries"):
        # Fallback if overall_summary is empty but per_file_summaries exist
        combined_summary_text = "\n".join(state.doc_summary.get("per_file_summaries", {}).values())

    if not combined_summary_text.strip():
        logger_nodes.warning("Combined documentation summary is empty. Defaulting to UNKNOWN.")
        return {
            "risk_tier": RiskTier.UNKNOWN, 
            "risk_classification_justification": "Risk tier not assessed as the combined documentation summary was empty.",
            "error_messages": list(state.error_messages)
        }

    # Prepare the LLM chain for risk classification
    llm = ChatOpenAI(temperature=0, openai_api_key=settings.OPENAI_API_KEY, model_name="gpt-3.5-turbo")

    prompt_template = PromptTemplate(
        input_variables=["documentation_summary"],
        template=(
            "You are an expert in the EU AI Act and AI system risk classification. "
            "Based on the following summarized documentation of an AI system, classify its potential risk tier according to the EU AI Act. "
            "The risk tiers are: PROHIBITED, HIGH, LIMITED, MINIMAL.\n\n"
            "Definitions for Risk Tiers (Simplified):\n"
            "- PROHIBITED AI: Systems posing an unacceptable risk (e.g., social scoring by public authorities, exploitation of vulnerabilities, certain real-time remote biometric identification). Assume this is rare unless explicitly stated.\n"
            "- HIGH-RISK AI: Systems in critical areas like transport, education, employment, essential services (credit scoring), law enforcement, migration, justice. These require strict compliance (risk management, data governance, transparency, human oversight, etc.). Consider if the system's failure could have severe consequences or impact fundamental rights.\n"
            "- LIMITED-RISK AI: Systems with transparency obligations (e.g., chatbots must disclose they are AI, AI-generated content must be labeled). Consider if the primary risk is lack of transparency.\n"
            "- MINIMAL-RISK AI: All other AI systems (e.g., AI in video games, spam filters). Most systems fall here if not otherwise classifiable.\n\n"
            "Documentation Summary:\n"
            "'''{documentation_summary}'''\n\n"
            "Output your classification in the following format:\n"
            "Risk Tier: [PROHIBITED|HIGH|LIMITED|MINIMAL]\n"
            "Justification: [Provide a concise explanation for your classification, referencing specific aspects of the documentation if possible, and explaining why it fits the chosen tier and not others. Be specific about how the system's described functionality aligns with the EU AI Act risk definitions.]"
        )
    )

    chain = prompt_template | llm | StrOutputParser()

    risk_tier_enum = RiskTier.UNKNOWN 
    justification = "Classification pending or failed."
    # local_error_messages is already defined

    try:
        logger_nodes.info("Invoking LLM for risk classification with combined summary...")
        response = await chain.ainvoke({"documentation_summary": combined_summary_text})
        logger_nodes.info(f"LLM Raw Response for risk classification: {response}")

        parsed_tier_from_llm = RiskTier.UNKNOWN # Default if parsing fails
        parsed_justification_from_llm = "LLM assessment did not yield a parseable justification."
        
        response_lines = response.strip().split('\n')
        for line in response_lines:
            if line.lower().startswith("risk tier:"):
                tier_value = line.split(":", 1)[1].strip().upper()
                try:
                    parsed_tier_from_llm = RiskTier[tier_value] 
                except KeyError:
                    logger_nodes.warning(f"LLM returned an invalid risk tier: {tier_value}. Defaulting to UNKNOWN.")
                    # parsed_tier_from_llm remains UNKNOWN
            elif line.lower().startswith("justification:"):
                parsed_justification_from_llm = line.split(":", 1)[1].strip()
        
        risk_tier_enum = parsed_tier_from_llm
        justification = parsed_justification_from_llm

        if risk_tier_enum == RiskTier.UNKNOWN and justification == "LLM assessment did not yield a parseable justification.":
             logger_nodes.warning(f"Failed to parse LLM response for risk classification. Response: {response}")
        else:
            logger_nodes.info(f"Classified risk tier: {risk_tier_enum.value} with justification: {justification}")

    except Exception as e:
        error_msg = f"Error during risk classification LLM call: {e}"
        logger_nodes.error(error_msg, exc_info=True)
        local_error_messages.append(error_msg)
        # risk_tier_enum remains UNKNOWN
        justification = f"An error occurred during classification: {str(e)}"

    return {
        "risk_tier": risk_tier_enum, 
        "risk_classification_justification": justification,
        "error_messages": local_error_messages
    }

async def generate_compliance_checklist_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing generate_compliance_checklist_node ---")
    
    checklist: List[ComplianceChecklistItem] = []
    repo_path = state.repo_local_path
    criterion_grep_results_map = state.criterion_grep_results if state.criterion_grep_results is not None else {}

    if not repo_path: # Keep this check for sanity
        logger_nodes.error("Repository path not found in state. Skipping compliance checklist generation.")
        return {"compliance_checklist": checklist, "error_messages": list(state.error_messages) + ["Repository path missing for checklist generation"]}

    current_risk_tier = state.risk_tier if state.risk_tier is not None else RiskTier.UNKNOWN

    # Load compliance criteria from YAML file
    compliance_criteria = INITIAL_COMPLIANCE_CRITERIA

    # Initialize LLM for deeper analysis if needed. Ensure OPENAI_API_KEY is set.
    llm_for_analysis = None
    try:
        llm_for_analysis = ChatOpenAI(model_name="gpt-4o-mini", temperature=0.1, openai_api_key=settings.OPENAI_API_KEY)
        logger_nodes.info("LLM for compliance checklist analysis initialized.")
    except Exception as e:
        logger_nodes.error(f"Failed to initialize ChatOpenAI for checklist analysis: {e}. LLM-based review will be skipped.")

    for criterion_def in compliance_criteria:
        item_id = criterion_def["id"]
        # Only check criteria relevant to the determined risk tier, or if risk tier is UNKNOWN (check all initially)
        if current_risk_tier != RiskTier.UNKNOWN and current_risk_tier not in criterion_def["relevant_risk_tiers"]:
            item = ComplianceChecklistItem(
                id=item_id,
                criterion=criterion_def["criterion"],
                description=criterion_def["description"],
                status=ComplianceCheckStatus.NOT_APPLICABLE,
                details=f"Not applicable for the current determined risk tier: {current_risk_tier.value}",
                relevant_risk_tiers=criterion_def["relevant_risk_tiers"]
            )
            checklist.append(item)
            continue

        logger_nodes.info(f"Processing compliance criterion: {criterion_def['criterion']}")
        found_evidence_for_criterion = []
        overall_status_for_criterion = ComplianceCheckStatus.NOT_EVIDENT
        details_message = "No direct keyword evidence found via initial scan."

        # 1. Process Grep Search Results
        grep_matches = criterion_grep_results_map.get(item_id)
        if grep_matches is None:
            logger_nodes.warning(f"Grep results not found in state for criterion ID: {item_id}. Marking as error for analysis.")
            overall_status_for_criterion = ComplianceCheckStatus.ERROR_ANALYZING
            details_message = f"Grep search results were not available for criterion '{criterion_def['criterion']}'. Analysis could not be performed."
        elif isinstance(grep_matches, list) and not grep_matches:
            # No grep matches, status remains NOT_EVIDENT for now (might be updated by fuzzy matching)
            details_message = f"No keyword matches found via grep for '{criterion_def['criterion']}'."
        elif isinstance(grep_matches, list) and grep_matches:
            overall_status_for_criterion = ComplianceCheckStatus.REQUIRES_REVIEW
            details_message = f"Keyword evidence found via grep for '{criterion_def['criterion']}'. Further review recommended."
            for match in grep_matches:
                if isinstance(match, dict) and all(k in match for k in ["File", "LineNumber", "LineContent"]):
                    evidence_str = f"[Grep Match] Found in {match.get('File', 'N/A')}:{match.get('LineNumber', 'N/A')}: {str(match.get('LineContent', 'N/A'))[:200]}..."
                    found_evidence_for_criterion.append(evidence_str)
                else:
                    logger_nodes.warning(f"Malformed grep match for criterion {item_id}: {match}")
                    found_evidence_for_criterion.append(f"[Grep Match] Malformed match data: {str(match)[:200]}...")
            if not found_evidence_for_criterion and overall_status_for_criterion == ComplianceCheckStatus.REQUIRES_REVIEW:
                overall_status_for_criterion = ComplianceCheckStatus.NOT_EVIDENT
                details_message = f"Keyword matches via grep were reported for '{criterion_def['criterion']}', but evidence details could not be extracted."
        else:
            logger_nodes.error(f"Unexpected data type for grep_matches for criterion ID: {item_id}. Type: {type(grep_matches)}. Marking as error.")
            overall_status_for_criterion = ComplianceCheckStatus.ERROR_ANALYZING
            details_message = f"Internal error: Unexpected format for grep search results for criterion '{criterion_def['criterion']}'."

        # 2. Process Fuzzy Matching Results
        project_fuzzy_matches = state.fuzzy_matches if state.fuzzy_matches is not None else []
        criterion_fuzzy_matches_found = False
        if isinstance(project_fuzzy_matches, list):
            for fuzzy_match in project_fuzzy_matches:
                if hasattr(fuzzy_match, 'criterion_id') and fuzzy_match.criterion_id == item_id:
                    criterion_fuzzy_matches_found = True
                    evidence_str = (
                        f"[Fuzzy Match] File: {getattr(fuzzy_match, 'file_path', 'N/A')}, "
                        f"Line: {getattr(fuzzy_match, 'line_number', 'N/A')}, "
                        f"Keyword: '{getattr(fuzzy_match, 'keyword_found', 'N/A')}', "
                        f"Matched Text: '{getattr(fuzzy_match, 'original_text_matched', 'N/A')}', "
                        f"Score: {getattr(fuzzy_match, 'score', 'N/A')}. "
                        f"Content: {str(getattr(fuzzy_match, 'line_content', 'N/A'))[:150]}..."
                    )
                    found_evidence_for_criterion.append(evidence_str)
            
            if criterion_fuzzy_matches_found:
                if overall_status_for_criterion == ComplianceCheckStatus.NOT_EVIDENT:
                    overall_status_for_criterion = ComplianceCheckStatus.REQUIRES_REVIEW
                    details_message = f"Fuzzy matches found for '{criterion_def['criterion']}' (no direct grep matches). Further review recommended."
                elif overall_status_for_criterion == ComplianceCheckStatus.REQUIRES_REVIEW:
                    # Already requires review from grep, add to details
                    details_message += " Fuzzy matches also found, providing additional context."
                # If ERROR_ANALYZING, fuzzy matches don't change that primary status but are still recorded as evidence.
        else:
            logger_nodes.warning("state.fuzzy_matches is not a list or is missing. Skipping fuzzy match processing.")

        # --- LLM Analysis for items requiring review ---
        if overall_status_for_criterion == ComplianceCheckStatus.REQUIRES_REVIEW and llm_for_analysis:
            logger_nodes.info(f"Performing LLM analysis for criterion: {criterion_def['criterion']} (ID: {item_id})")
            
            # Consolidate evidence for the LLM. For a real case, we might fetch more context around each grep match.
            # For now, just join the line contents.
            context_for_llm = "\n".join([ev.split(": ", 1)[1] if ": " in ev else ev for ev in found_evidence_for_criterion])
            
            if not context_for_llm.strip():
                logger_nodes.warning(f"No context extracted from grep evidence for LLM analysis of {item_id}. Skipping LLM step.")
            else:
                llm_prompt_template_text = (
                    "You are an AI compliance analyst specializing in the EU AI Act. "
                    "Review the following text snippets found in a software project's files. These snippets are potential evidence related to the compliance criterion: '{criterion_title}'.\n\n"
                    "Criterion Description: {criterion_description}\n\n"
                    "Evidence Snippets:\n"
                    "'''{evidence_context}'''\n\n"
                    "Based *only* on the provided snippets and the criterion description, assess if the evidence suggests compliance. "
                    "Output your assessment strictly in the following format (no preambles or explanations before or after this structure):\n"
                    "Status: [MET|NOT_MET|PARTIALLY_MET|REQUIRES_REVIEW]\n"
                    "Justification: [Your concise justification for the status, explaining how the snippets support or fail to support the criterion. If the snippets are insufficient for a definitive judgment, explain why and maintain REQUIRES_REVIEW.]"
                )
                
                prompt = PromptTemplate(
                    input_variables=["criterion_title", "criterion_description", "evidence_context"],
                    template=llm_prompt_template_text
                )
                
                chain = prompt | llm_for_analysis | StrOutputParser()
                llm_assessment_prompt_str = prompt.format(criterion_title=criterion_def['criterion'], criterion_description=criterion_def['description'], evidence_context=context_for_llm)

                try:
                    logger_nodes.info(f"  Invoking LLM for {item_id} with {len(found_evidence_for_criterion)} pieces of evidence.")
                    # In a real LangGraph setup, this might be a separate node or a tool call.
                    # For now, direct call within the node for simulation.
                    llm_response_str = await chain.ainvoke({
                        "criterion_title": criterion_def['criterion'],
                        "criterion_description": criterion_def['description'],
                        "evidence_context": context_for_llm
                    })
                    logger_nodes.info(f"  LLM raw response for {item_id}: {llm_response_str}")

                    # Parse LLM response
                    # Expecting format: "Status: [STATUS]\nJustification: [TEXT]"
                    lines = llm_response_str.strip().split('\n')
                    parsed_llm_status = None
                    parsed_llm_justification = "LLM assessment did not yield a parseable justification."
                    
                    response_lines = llm_response_str.strip().split('\n')
                    for line in response_lines:
                        if line.lower().startswith("status:"):
                            status_val = line.split(":", 1)[1].strip().upper()
                            try:
                                parsed_llm_status = ComplianceCheckStatus[status_val]
                            except KeyError:
                                logger_nodes.warning(f"LLM returned an invalid status '{status_val}' for {item_id}. Retaining REQUIRES_REVIEW.")
                                parsed_llm_status = ComplianceCheckStatus.REQUIRES_REVIEW # Fallback
                        elif line.lower().startswith("justification:"):
                            parsed_llm_justification = line.split(":", 1)[1].strip()
                    
                    if parsed_llm_status:
                        overall_status_for_criterion = parsed_llm_status
                        details_message = f"LLM Assessment: {parsed_llm_justification}" # Override previous details
                        # Optionally, append LLM justification to existing evidence or store separately
                        found_evidence_for_criterion.append(f"LLM Justification: {parsed_llm_justification}")
                    else:
                        details_message += " | LLM assessment parsing failed. Original grep review status retained."
                        logger_nodes.warning(f"Failed to parse LLM status for {item_id}. Response: {llm_response_str}")

                except Exception as llm_exc:
                    logger_nodes.error(f"Error during LLM analysis for {item_id}: {llm_exc}")
                    details_message += f" | LLM analysis failed: {str(llm_exc)}"
                    # Status remains REQUIRES_REVIEW from grep if LLM fails
        
        item = ComplianceChecklistItem(
            id=item_id,
            criterion=criterion_def["criterion"],
            description=criterion_def["description"],
            status=overall_status_for_criterion,
            evidence=found_evidence_for_criterion,
            details=details_message,
            relevant_risk_tiers=criterion_def["relevant_risk_tiers"]
        )
        checklist.append(item)

    logger_nodes.info(f"Generated compliance checklist with {len(checklist)} items.")
    for item in checklist:
        logger_nodes.debug(f"  Item: {item.id}, Status: {item.status.value}")

    return {"compliance_checklist": checklist, "error_messages": list(state.error_messages or [])}


# --- Placeholder for lookup_checklist_node (if it was meant to be separate or was removed, ensure correct structure)
# Note: The diff showed lookup_checklist_node was removed. If it's needed, it should be re-added or confirmed removed.
# For now, focusing on fixing generate_compliance_checklist_node and then the rest of the file structure.

# --- Placeholder for prepare_final_response_node ---
async def prepare_final_response_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing prepare_final_response_node ---")
    
    # Ensure default values if parts of the state are not populated
    scan_id = state.scan_id or "unknown_scan_id"
    repo_url = state.input_model.repo_url if state.input_model else "unknown_repo_url"
    risk_tier = state.risk_tier or RiskTier.UNKNOWN # Default if not set
    risk_justification = state.risk_classification_justification or "Justification not available."
    code_analysis_score = state.code_analysis_score if state.code_analysis_score is not None else 0.0
    # detailed_findings = state.compliance_checklist if state.compliance_checklist else [] # Using compliance_checklist as detailed_findings
    # For now, let's keep detailed_findings as a placeholder or a more generic list
    detailed_findings = [] # Placeholder, to be populated by actual findings later
    if state.compliance_checklist:
        detailed_findings.extend(state.compliance_checklist)
    
    # Construct a more meaningful overall summary
    overall_summary = f"Scan completed for {repo_url}. "
    overall_summary += f"The system has been preliminarily classified as {risk_tier.value} risk. "
    if risk_justification != "Justification not available." and risk_justification != "No documentation provided for analysis." and risk_justification != "Classification failed or pending." and risk_justification != "Could not parse LLM response accurately." and not risk_justification.startswith("LLM initialization failed") and not risk_justification.startswith("An error occurred during classification"):
        overall_summary += f"Justification: {risk_justification} "
    overall_summary += f"Code analysis score: {code_analysis_score:.2f}."

    final_response = APIScanResponse(
        scan_id=scan_id,
        repo_url=repo_url,
        overall_summary=overall_summary, # Updated placeholder text
        risk_tier=risk_tier,
        risk_classification_justification=risk_justification, # Added field
        code_analysis_score=code_analysis_score, 
        detailed_code_violations=state.detailed_code_violations if state.detailed_code_violations else [],
        # detailed_findings=detailed_findings, # Placeholder for now, can use compliance_checklist
        recommendations=[], # Placeholder
        timestamp=datetime.utcnow().isoformat(),
        error_messages=state.error_messages if state.error_messages else []
    )
    logger_nodes.info(f"Prepared final response: {final_response.model_dump_json(indent=2)}")
    return {"final_api_response": final_response, "error_messages": list(state.error_messages or [])}


# --- Placeholder for persist_scan_results_node ---
async def persist_scan_results_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing persist_scan_results_node ---")

    if not state.scan_id:
        logger_nodes.error("Scan ID is missing. Cannot persist results.")
        # Potentially add to error_messages in state if that's how errors are bubbled up
        return {"error_messages": list(state.error_messages or []) + ["Scan ID missing for persistence"]}

    if not state.final_api_response:
        logger_nodes.error("Final API response is missing. Cannot persist results.")
        return {"error_messages": list(state.error_messages or []) + ["Final API response missing for persistence"]}

    try:
        persistence_data = ScanPersistenceData(
            scan_id=state.scan_id,
            user_id=state.input_model.user_id if state.input_model and state.input_model.user_id else "anonymous",
            repo_url=state.input_model.repo_url if state.input_model else "unknown_repo_url",
            scan_timestamp=datetime.utcnow(), # Or from state.final_api_response.timestamp if preferred
            status="completed", # Assuming completion if this node is reached
            risk_tier=state.risk_tier, # From state after classification
            risk_classification_justification=state.risk_classification_justification, # From state
            code_analysis_score=state.code_analysis_score,
            # Store the entire final response as JSON for easy retrieval/rehydration
            final_response_json=state.final_api_response.model_dump(), 
            # Populate other fields as necessary from state or final_api_response
            # e.g., extracted_files_count, summarized_docs_count, etc.
            # For now, focusing on the core elements related to recent changes.
            error_messages=state.error_messages if state.error_messages else []
        )

        logger_nodes.info(f"Prepared data for persistence: {persistence_data.model_dump_json(indent=2)}")

        # Placeholder for actual database interaction
        logger_nodes.warning("Actual persistence logic (database save) is still a placeholder.")
        # Example of what would happen here:
        # async with get_db_session() as db_session:
        #     await crud_scan_record.create_or_update_scan_persistence_data(db_session, persistence_data)
        
        # For now, we can store it in the state if that's useful for testing or if no DB is connected
        # state.scan_persistence_data = persistence_data 

    except Exception as e:
        logger_nodes.error(f"Error preparing data for persistence: {e}")
        return {"error_messages": list(state.error_messages or []) + [f"Persistence preparation error: {e}"]}

    return {"error_messages": list(state.error_messages or [])} # Return current error messages


# Graph definition
