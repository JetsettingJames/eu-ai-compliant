# app/graph_nodes.py

from typing import Dict, Any, Optional, List, Tuple, Set
from collections import defaultdict
from .models import (
    RepoInputModel, ScanGraphState, RepoInfo,
    CodeAnalysisResult, CodeSignal, RiskTier, APIScanResponse,
    ScanPersistenceData, CodeViolationDetail, ComplianceObligation, ComplianceChecklistItem,
    RepositoryFile, FuzzyMatchResult
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

logger_nodes = get_logger(__name__) 

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

    python_files = state.discovered_files.get('python', [])
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

async def analyze_code_complexity_node(state: ScanGraphState) -> dict:
    """Analyzes discovered Python files for code complexity metrics."""
    logger_nodes.info("--- Executing AnalyzeCodeComplexityNode ---")
    # This node calculates cyclomatic complexity for Python files.

    # Initialize local error messages and success counter
    local_error_messages = [] 
    files_processed_successfully = 0

    code_ast_analysis_results: Dict[str, Any] = {}
    python_files_relative_paths = state.discovered_files.get("python", [])

    if not python_files_relative_paths:
        logger_nodes.info("No Python files found to analyze for complexity.")
    else:
        logger_nodes.info(f"Analyzing {len(python_files_relative_paths)} Python files for complexity...")

    repo_local_path = state.repo_local_path
    if not repo_local_path or not os.path.isdir(repo_local_path):
        error_msg = f"Invalid or missing repo_local_path: {repo_local_path}"
        logger_nodes.error(error_msg)
        local_error_messages.append(error_msg)
        return {
            "code_complexity": None,
            "error_messages": list(state.error_messages) + local_error_messages
        }

    cumulative_complexity = 0

    for relative_file_path in python_files_relative_paths:
        absolute_file_path = os.path.join(repo_local_path, relative_file_path)
        try:
            if not os.path.exists(absolute_file_path):
                err_msg = f"File not found at constructed path: {absolute_file_path} (original relative: {relative_file_path})"
                logger_nodes.error(err_msg)
                local_error_messages.append(err_msg)
                continue

            with open(absolute_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            raw_metrics = raw_analyze(content)
            # Fix 1: Remove ignore_names=True. cc_visit returns a list of radon block objects.
            complexity_blocks = cc_visit(content)

            # Fix 2: Correctly sum complexities from the list of blocks
            current_file_total_complexity = 0
            block_details_for_file = []
            if complexity_blocks:
                current_file_total_complexity = sum(b.complexity for b in complexity_blocks)
                for block in complexity_blocks:
                    block_details_for_file.append({
                        "name": getattr(block, 'name', 'N/A'),
                        "type": str(getattr(block, 'type', 'N/A')),
                        "lineno": getattr(block, 'lineno', 0),
                        "col_offset": getattr(block, 'col_offset', 0),
                        "endline": getattr(block, 'endline', 0),
                        "complexity": getattr(block, 'complexity', 0),
                    })
            
            cumulative_complexity += current_file_total_complexity
            files_processed_successfully += 1

            code_ast_analysis_results[relative_file_path] = {
                "complexity_blocks": block_details_for_file, # Store list of dicts
                "raw_analysis": raw_metrics._asdict() if raw_metrics else {} # Convert namedtuple to dict
            }
        except Exception as e:
            err_msg = f"Error analyzing file {relative_file_path} for complexity: {e}"
            logger_nodes.error(err_msg, exc_info=True)
            local_error_messages.append(err_msg)
    
    avg_complexity = 0
    if files_processed_successfully > 0:
        avg_complexity = cumulative_complexity / files_processed_successfully

    output_code_complexity_dict = {
        "average_complexity": avg_complexity,
        "details_per_file": code_ast_analysis_results
    }

    return {
        "code_complexity": output_code_complexity_dict,
        "error_messages": list(state.error_messages) + local_error_messages
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
    extracted_markdown_docs: List[Tuple[str, str, List[str]]] = list(state.extracted_markdown_docs) if state.extracted_markdown_docs else []
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
                            extracted_markdown_docs.append((rel_path, text_content, headings))
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

# --- Placeholder for summarize_documentation_node ---
async def summarize_documentation_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing summarize_documentation_node (Placeholder) ---")
    logger_nodes.warning("summarize_documentation_node is a placeholder. Actual summarization logic needed.")
    return {"documentation_summary": "Placeholder summary", "error_messages": list(state.error_messages)}

# --- Placeholder for classify_risk_tier_node ---
async def classify_risk_tier_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing classify_risk_tier_node (Placeholder) ---")
    logger_nodes.warning("classify_risk_tier_node is a placeholder. Actual risk classification logic needed.")
    return {"risk_tier": RiskTier.MINIMAL, "error_messages": list(state.error_messages)}

# --- Placeholder for lookup_checklist_node ---
async def lookup_checklist_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing lookup_checklist_node (Placeholder) ---")
    logger_nodes.warning("lookup_checklist_node is a placeholder. Actual checklist lookup logic needed.")
    return {"compliance_checklist": [], "error_messages": list(state.error_messages)}

# --- Placeholder for prepare_final_response_node ---
async def prepare_final_response_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing prepare_final_response_node (Placeholder) ---")
    logger_nodes.warning("prepare_final_response_node is a placeholder. Actual response preparation logic needed.")
    
    # Use state.code_analysis_score (calculated by calculate_code_analysis_score_node)
    # instead of trying to derive from state.code_complexity.
    current_code_analysis_score = state.code_analysis_score if state.code_analysis_score is not None else 0.0

    final_response = APIScanResponse(
        scan_id=state.scan_id or "unknown_scan_id",
        repo_url=state.input_model.repo_url if state.input_model else "unknown_repo_url",
        overall_summary="Placeholder overall summary. Full logic pending.", # Updated placeholder text
        risk_tier=state.risk_tier or RiskTier.MINIMAL,
        code_analysis_score=current_code_analysis_score, 
        detailed_findings=state.checklist if state.checklist else [], # Example: use checklist as detailed_findings
        recommendations=[], # Placeholder
        timestamp=datetime.utcnow().isoformat()
    )
    # Return with the key 'final_api_response' as expected by graph state/channels
    return {"final_api_response": final_response, "error_messages": list(state.error_messages)}

# --- Placeholder for persist_scan_results_node ---
async def persist_scan_results_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing persist_scan_results_node (Placeholder) ---")
    logger_nodes.warning("persist_scan_results_node is a placeholder. Actual persistence logic needed.")
    # Actual logic to save state.final_response_model to DB
    # Example: await crud_scan_record.update_scan_record_with_results(db_session, state.scan_id, state.final_response_model)
    return {"error_messages": list(state.error_messages)}
