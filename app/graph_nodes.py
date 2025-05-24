# app/graph_nodes.py

from typing import Dict, Any, Optional, List, Tuple, Set
from collections import defaultdict
from .models import (
    RepoInputModel, ScanGraphState, RepoInfo,
    CodeAnalysisResult, CodeSignal, RiskTier, APIScanResponse,
    ScanPersistenceData, CodeViolationDetail, ComplianceObligation, ComplianceChecklistItem,
    RepositoryFile, FuzzyMatchResult,
    ComplianceCriterion, # Added this line
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

def load_compliance_criteria() -> List[ComplianceCriterion]:
    """Loads compliance criteria from the YAML configuration file and parses them into ComplianceCriterion models."""
    try:
        with open(COMPLIANCE_CRITERIA_PATH, 'r') as f:
            raw_criteria_data = yaml.safe_load(f)
        
        parsed_criteria: List[ComplianceCriterion] = []
        if not isinstance(raw_criteria_data, list):
            logger_nodes.error(f"Compliance criteria YAML content is not a list. Path: {COMPLIANCE_CRITERIA_PATH}")
            return []

        for i, criterion_dict in enumerate(raw_criteria_data):
            if not isinstance(criterion_dict, dict):
                logger_nodes.warning(f"Item at index {i} in compliance_criteria.yaml is not a dictionary. Skipping.")
                continue
            try:
                # Pydantic will automatically handle 'triggered_by_code_categories' using its default if not present
                # It will also validate other fields.
                criterion_model = ComplianceCriterion(**criterion_dict)
                parsed_criteria.append(criterion_model)
            except ValidationError as e_val:
                logger_nodes.error(f"Validation error for criterion at index {i} ('{criterion_dict.get('id', 'N/A')}') in compliance_criteria.yaml: {e_val}")
            except Exception as e_item:
                logger_nodes.error(f"Error parsing criterion at index {i} ('{criterion_dict.get('id', 'N/A')}') in compliance_criteria.yaml: {e_item}")
        
        logger_nodes.info(f"Successfully loaded and parsed {len(parsed_criteria)} compliance criteria.")
        return parsed_criteria
    except FileNotFoundError:
        logger_nodes.error(f"Compliance criteria file not found at {COMPLIANCE_CRITERIA_PATH}. Returning empty criteria list.")
        return []
    except yaml.YAMLError as e_yaml:
        logger_nodes.error(f"Error parsing YAML in {COMPLIANCE_CRITERIA_PATH}: {e_yaml}. Returning empty criteria list.")
        return []
    except Exception as e:
        logger_nodes.error(f"An unexpected error occurred while loading compliance criteria: {e}. Returning empty criteria list.")
        return []

# Load compliance criteria once when the module is imported
# This makes it available to all nodes without reloading, assuming graph_nodes.py is imported once.
INITIAL_COMPLIANCE_CRITERIA: List[ComplianceCriterion] = load_compliance_criteria()

# Define categories of sensitive libraries that might indicate specific compliance obligations
# or risk areas. The key is the policy category, and the value is a list of module names.
SENSITIVE_LIBRARIES_CONFIG = {
    "gpai": [  # General Purpose AI & Foundational Models
        "transformers", "tensorflow", "tf", "torch", "pytorch", "keras", "scikit-learn", "sklearn",
        "openai", "anthropic", "langchain", "google.generativeai", "vertexai", "cohere",
        "sentence_transformers", "gensim", "spacy", "nltk"
    ],
    "biometric_processing": [ # Biometric identification, categorization
        "face_recognition", "deepface", "cv2", "dlib", "retinaface", "mediapipe",
        "pykaldi" # for speech/speaker recognition
    ],
    "emotion_recognition": [ # Inferring emotions, intentions from various data types
        "fer", "deepface", "nrclex", "vaderSentiment", "text2emotion", "emopy", "speechbrain"
    ],
    "surveillance_and_monitoring": [ # Broad surveillance capabilities, object tracking, activity recognition
        "yolov5", "yolov7", "yolov8", "detectron2", "cv2", # Object detection often used in surveillance
        "pyshark", "scapy", # Network traffic analysis if used for monitoring individuals
        "deepstream"
    ],
    "predictive_analytics_law_enforcement": [ # Predictive policing, risk assessment for recidivism
        # Often custom, but might use general ML libs from 'gpai' or specific graph analysis
        "networkx", # If used for social network analysis in this context
        "geopandas" # If used for hotspot mapping
    ],
    "critical_decision_making_employment": [ # Recruitment, promotion, termination, task allocation
        # Often custom or SaaS, underlying tech might use common NLP/ML libs from 'gpai'
        # This category might require more than just import scanning in the future.
    ],
    "critical_decision_making_essential_services": [ # Credit scoring, insurance, access to public benefits
        # Often custom, but might use general ML libs from 'gpai'
        "xgboost", "lightgbm", "catboost" # Common in financial/risk modeling
    ],
    "safety_critical_control": [ # AI controlling critical infrastructure, robotics, autonomous vehicles
        "dronekit", "pyro", "roslibpy", "carla", "airsim"
    ],
    "generative_ai_media_manipulation": [ # Deepfakes, synthetic media generation
        "stylegan", "wav2lip", "faceswap", "deepfacelab"
    ]
    # "social_scoring": [], # Placeholder - often context-dependent
    # "dark_patterns": [],  # Placeholder - more about UI/UX patterns than specific libs
    # "manipulative_ai": [], # Placeholder - often overlaps with emotion/persuasion, context is key
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
    
    if not state.scan_id or not state.input_model:
        error_msg = "Scan ID or Input Model not found in initial state."
        logger_nodes.error(error_msg)
        return {"error_messages": state.error_messages + [error_msg]}

    logger_nodes.info(f"Initial setup for scan_id: {state.scan_id} with input: {state.input_model.repo_url}")

    # Load compliance criteria
    criteria_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'data', 'obligations_data.json')
    loaded_criteria = []
    try:
        with open(criteria_path, 'r') as f:
            loaded_criteria = json.load(f)
        logger_nodes.info(f"Successfully loaded compliance criteria from {criteria_path}")
    except Exception as e:
        error_msg = f"Error loading compliance criteria: {e}"
        logger_nodes.error(error_msg)
        return {
            "error_messages": state.error_messages + [error_msg],
            "repo_url": state.input_model.repo_url,
            "compliance_criteria": [] # Return empty list on error
        }

    return {
        "repo_url": state.input_model.repo_url, # Pass along essential info
        "compliance_criteria": loaded_criteria, # Add loaded criteria to state
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

async def search_compliance_terms_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing search_compliance_terms_node ---")
    file_cache = state.file_content_cache
    criteria = state.compliance_criteria # Loaded by initial_setup_node
    error_messages = list(state.error_messages)
    criterion_grep_results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    if not file_cache:
        logger_nodes.warning("File cache is empty. Skipping compliance term search.")
        return {"criterion_grep_results": {}, "error_messages": error_messages}

    if not criteria:
        logger_nodes.warning("Compliance criteria not loaded. Skipping compliance term search.")
        # Potentially add an error message if this is unexpected
        # error_messages.append("Compliance criteria failed to load, cannot perform term search.")
        return {"criterion_grep_results": {}, "error_messages": error_messages}

    logger_nodes.info(f"Searching for compliance terms across {len(file_cache)} cached files for {len(criteria)} criteria.")

    for criterion in criteria:
        criterion_id = criterion.get('id')
        search_terms = criterion.get('search_terms')

        if not criterion_id or not search_terms:
            logger_nodes.warning(f"Criterion missing ID or search_terms: {criterion.get('title', 'Unknown')}. Skipping.")
            continue

        # Compile regex patterns for case-insensitive search for all terms in this criterion
        # We'll search for any of the terms in a line.
        # For simplicity, let's iterate terms and then lines, then files.
        # More optimized would be to build a combined regex per criterion if terms are many.

        for file_path, content in file_cache.items():
            if not content: # Skip empty files
                continue
            lines = content.splitlines()
            for line_num, line_text in enumerate(lines, 1):
                for term in search_terms:
                    # Perform case-insensitive search
                    if re.search(re.escape(term), line_text, re.IGNORECASE):
                        match_info = {
                            "file_path": file_path,
                            "line_number": line_num,
                            "line_content": line_text.strip(),
                            "term_found": term,
                            "criterion_id": criterion_id
                        }
                        criterion_grep_results[criterion_id].append(match_info)
                        # Found a term in this line for this criterion, can break from inner term loop for this line
                        # if we only care about one match per line per criterion.
                        # For now, let's log all term matches on a line.
    
    logger_nodes.info(f"Compliance term search completed. Found matches for {len(criterion_grep_results)} criteria.")
    for crit_id, matches in criterion_grep_results.items():
        logger_nodes.debug(f"Criterion '{crit_id}': {len(matches)} matches found.")

    return {
        "criterion_grep_results": dict(criterion_grep_results), # Convert defaultdict to dict for state
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
        logger_nodes.error("OpenAI API key not configured. Skipping documentation summarization.")
        local_error_messages.append("OpenAI API key not configured. Skipping documentation summarization.")
        return {
            "doc_summary": ["Skipped due to missing OpenAI API key."],
            "error_messages": local_error_messages
        }

    markdown_docs = state.extracted_markdown_docs
    if not markdown_docs:
        logger_nodes.info("No Markdown documents found to summarize.")
        return {
            "doc_summary": ["No Markdown documents found."],
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
        logger_nodes.error(f"Failed to initialize LLM for summarization: {e}")
        local_error_messages.append(f"Failed to initialize summarization model: {e}")
        return {
            "doc_summary": ["Failed to initialize summarization model."],
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
    
    final_doc_summary_list: List[str] = []
    if per_file_summaries:
        final_doc_summary_list = list(per_file_summaries.values())
    elif markdown_docs: # No summaries, but docs existed
        final_doc_summary_list = ["Could not generate summaries for any document."]
    else: # No markdown_docs initially, this case is covered by early return.
          # This path implies markdown_docs existed but per_file_summaries is empty.
          # However, the above condition `elif markdown_docs:` handles this.
          # For safety, if somehow markdown_docs is false here (e.g. modified state), default message.
        final_doc_summary_list = ["No documents were available or summarized."]

    # Log per-file summaries for debugging if needed
    for file_path, summary_content in per_file_summaries.items():
        logger_nodes.debug(f"Summary for {file_path}: {summary_content[:200]}...")

    return {
        "doc_summary": final_doc_summary_list,
        "error_messages": local_error_messages
    }


async def classify_risk_tier_node(state: ScanGraphState) -> dict:
    """
    Classifies the AI system's risk tier based on summarized documentation and EU AI Act criteria using an LLM.
    """
    logger_nodes.info("Starting risk tier classification...")
    local_error_messages = list(state.error_messages) # Initialize error messages list

    if not state.doc_summary:
        logger_nodes.warning("No documentation summary available to classify risk tier. Defaulting to UNKNOWN.")
        return {
            "risk_tier": RiskTier.UNKNOWN, 
            "risk_classification_justification": "Risk tier not assessed as the combined documentation summary was empty.",
            "error_messages": local_error_messages # Use initialized list
        }

    # Combine summaries into a single text for the LLM prompt
    # combined_summary_text = "\n".join(summarized_docs.get("per_file_summaries", {}).values())
    # Using overall_summary as it's more concise and already an aggregation
    combined_summary_text = "\n".join(state.doc_summary)
    if not combined_summary_text.strip():
        logger_nodes.warning("Combined documentation summary is empty. Defaulting to UNKNOWN.")
        return {
            "risk_tier": RiskTier.UNKNOWN, 
            "risk_classification_justification": "Risk tier not assessed as the combined documentation summary was empty.",
            "error_messages": local_error_messages # Use initialized list
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
            "Justification: [Your concise justification for the classification, referencing specific aspects of the documentation if possible, and explaining why it fits the chosen tier and not others. Be specific about how the system's described functionality aligns with the EU AI Act risk definitions.]"
        )
    )

    chain = prompt_template | llm | StrOutputParser()

    risk_tier_enum = RiskTier.UNKNOWN 
    justification = "Classification pending or failed."
    # local_error_messages is already defined by initialization at the top

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
        error_msg = f"Error during LLM risk classification: {e}"
        logger_nodes.error(error_msg, exc_info=True)
        local_error_messages.append(error_msg)
        return {
            "risk_tier": RiskTier.UNKNOWN,
            "risk_classification_justification": f"Failed to classify risk tier due to an error: {e}",
            "error_messages": local_error_messages
        }

    return {
        "risk_tier": risk_tier_enum,
        "risk_classification_justification": justification,
        "error_messages": local_error_messages
    }

async def generate_compliance_checklist_node(state: ScanGraphState) -> dict:
    logger_nodes.info(f"--- Executing generate_compliance_checklist_node ---")
    logger_nodes.info(f"generate_compliance_checklist_node: state.risk_tier is {state.risk_tier} (type: {type(state.risk_tier)})") # ADDED LOG
    local_error_messages = list(state.error_messages or []) # Ensure initialization with a list
    
    checklist: List[ComplianceChecklistItem] = []
    added_criterion_ids = set() # To avoid duplicate checklist items

    if not state.repo_local_path:
        logger_nodes.error("Repository path not found in state. Skipping compliance checklist generation.")
        return {"compliance_checklist": checklist, "error_messages": local_error_messages + ["Repository path missing for checklist generation"]}

    current_risk_tier_value = state.risk_tier.value if state.risk_tier is not None else RiskTier.UNKNOWN.value
    logger_nodes.info(f"Current risk tier for checklist generation: {current_risk_tier_value}")

    all_compliance_criteria = INITIAL_COMPLIANCE_CRITERIA # Using the globally loaded Pydantic models
    if not all_compliance_criteria:
        logger_nodes.error("INITIAL_COMPLIANCE_CRITERIA is empty. Cannot generate checklist.")
        return {
            "compliance_checklist": checklist, 
            "error_messages": local_error_messages + ["Initial compliance criteria not loaded or empty."]
        }

    llm_for_analysis = None # Initialize outside the loop
    try:
        llm_for_analysis = ChatOpenAI(model_name="gpt-4o-mini", temperature=0.1, openai_api_key=settings.OPENAI_API_KEY)
        logger_nodes.info("LLM for compliance checklist analysis initialized.")
    except Exception as e:
        err_msg = f"Failed to initialize ChatOpenAI for checklist analysis: {e}. LLM-based review will be skipped."
        logger_nodes.error(err_msg)
        local_error_messages.append(err_msg)

    for criterion_model in all_compliance_criteria:
        if not isinstance(criterion_model, ComplianceCriterion):
            logger_nodes.warning(f"Skipping item in compliance_criteria, not a ComplianceCriterion model: {criterion_model}")
            continue

        criterion_id = criterion_model.id
        criterion_title = criterion_model.criterion

        # 1. Check relevance by risk tier
        is_relevant_for_tier = current_risk_tier_value in criterion_model.relevant_risk_tiers
        logger_nodes.debug(f"Criterion '{criterion_id}': Relevant for current tier '{current_risk_tier_value}'? {is_relevant_for_tier}. (Criterion tiers: {criterion_model.relevant_risk_tiers})")

        # 2. Check relevance by code violation categories
        is_relevant_by_code_category = False
        if state.detailed_code_violations and criterion_model.triggered_by_code_categories:
            for violation in state.detailed_code_violations:
                if violation.policy_category in criterion_model.triggered_by_code_categories:
                    is_relevant_by_code_category = True
                    logger_nodes.info(f"Criterion '{criterion_id}' triggered by code violation category '{violation.policy_category}'.")
                    break 
        
        if not (is_relevant_for_tier or is_relevant_by_code_category):
            logger_nodes.debug(f"Criterion '{criterion_id}' is not relevant by tier or code category. Skipping.")
            continue

        if criterion_id in added_criterion_ids:
            logger_nodes.debug(f"Criterion '{criterion_id}' already added to checklist. Skipping duplicate.")
            continue

        # Determine status and gather evidence for this criterion
        # (This part of the logic needs to be adapted from the original function, using criterion_model)
        current_status = ComplianceCheckStatus.NOT_EVIDENT # Default, changed from NOT_ASSESSED
        evidence_summary = "No specific evidence gathered for this item yet. Status defaults to NOT_EVIDENT."
        supporting_documentation: List[str] = []
        code_references: List[str] = [] # Ensure this will store strings

        # Initialize lists to hold references for the current criterion
        # supporting_documentation: List[str] = []
        # code_references: List[str] = [] # Ensure this will store strings
        # evidence_summary = "No specific evidence found or summarized programmatically."
        # current_status = ComplianceCheckStatus.NOT_EVIDENT # Default status

        # --- Populate supporting_documentation (ensure strings) ---
        # Example for human_oversight_doc_findings (adapt for others if necessary)
        if criterion_id in (state.human_oversight_doc_findings or {}):
            finding = state.human_oversight_doc_findings[criterion_id]
            if isinstance(finding, dict) and 'summary' in finding:
                supporting_documentation.append(f"Human Oversight Doc Finding ({criterion_id}): {finding['summary']}")
            elif isinstance(finding, str):
                supporting_documentation.append(f"Human Oversight Doc Finding ({criterion_id}): {finding}")
            else:
                supporting_documentation.append(f"Human Oversight Doc Finding ({criterion_id}): {str(finding)}")
        
        # (Add similar blocks for data_governance_doc_findings and transparency_doc_findings if they contribute)
        # For example:
        if criterion_id in (state.data_governance_doc_findings or {}):
            finding = state.data_governance_doc_findings[criterion_id]
            # Convert finding to string appropriately
            supporting_documentation.append(f"Data Governance Doc Finding ({criterion_id}): {str(finding)}")

        if criterion_id in (state.transparency_doc_findings or {}):
            finding = state.transparency_doc_findings[criterion_id]
            # Convert finding to string appropriately
            supporting_documentation.append(f"Transparency Doc Finding ({criterion_id}): {str(finding)}")


        # --- Populate code_references (ensure strings) ---
        # Check if this criterion is triggered by any code violation categories
        code_categories_for_criterion = getattr(criterion_model, 'triggered_by_code_categories', [])
        if code_categories_for_criterion and state.detailed_code_violations:
            triggered_by_code_violation = False
            for violation in state.detailed_code_violations:
                if violation.policy_category in code_categories_for_criterion:
                    # Convert CodeViolationDetail object to a descriptive string
                    violation_str = (
                        f"Code Violation: {violation.policy_category} in '{violation.file_path}' (line {violation.line_number}). "
                        f"Description: {violation.description}. Code: '{violation.violating_code or 'N/A'}'"
                    )
                    code_references.append(violation_str)
                    triggered_by_code_violation = True
            if triggered_by_code_violation:
                evidence_summary = "Code violations found related to this criterion. Review needed."
                logger_nodes.info(f"DIAGNOSTIC (Block 1 Entry): About to access ComplianceCheckStatus. ID: {id(ComplianceCheckStatus)}, Type: {type(ComplianceCheckStatus)}")
                try:
                    logger_nodes.info(f"DIAGNOSTIC (Block 1 - Inside Try): dir(ComplianceCheckStatus): {dir(ComplianceCheckStatus)}")
                    status_to_assign = ComplianceCheckStatus.NEEDS_REVIEW
                    logger_nodes.info(f"DIAGNOSTIC (Block 1): Successfully accessed ComplianceCheckStatus.NEEDS_REVIEW. Value: {status_to_assign}")
                    current_status = status_to_assign
                    logger_nodes.info(f"DIAGNOSTIC (Block 1): Successfully assigned to current_status.")
                except AttributeError as e_block1:
                    logger_nodes.error(f"DIAGNOSTIC (Block 1): AttributeError accessing ComplianceCheckStatus.NEEDS_REVIEW: {e_block1}")
                    logger_nodes.error(f"DIAGNOSTIC (Block 1 - Inside Except): dir(ComplianceCheckStatus) after error: {dir(ComplianceCheckStatus)}")
                    logger_nodes.error(f"DIAGNOSTIC (Block 1): ComplianceCheckStatus at error: ID: {id(ComplianceCheckStatus)}, Type: {type(ComplianceCheckStatus)}")
                    raise
        if code_references and current_status == ComplianceCheckStatus.NOT_EVIDENT:
             evidence_summary = "Code signals relevant to this criterion were detected. Manual review recommended."
             logger_nodes.info(f"DIAGNOSTIC (Block 2 Entry): About to access ComplianceCheckStatus. ID: {id(ComplianceCheckStatus)}, Type: {type(ComplianceCheckStatus)}")
             try:
                 logger_nodes.info(f"DIAGNOSTIC (Block 2 - Inside Try): dir(ComplianceCheckStatus): {dir(ComplianceCheckStatus)}")
                 status_to_assign = ComplianceCheckStatus.NEEDS_REVIEW
                 logger_nodes.info(f"DIAGNOSTIC (Block 2): Successfully accessed ComplianceCheckStatus.NEEDS_REVIEW. Value: {status_to_assign}")
                 current_status = status_to_assign
                 logger_nodes.info(f"DIAGNOSTIC (Block 2): Successfully assigned to current_status.")
             except AttributeError as e_block2:
                 logger_nodes.error(f"DIAGNOSTIC (Block 2): AttributeError accessing ComplianceCheckStatus.NEEDS_REVIEW: {e_block2}")
                 logger_nodes.error(f"DIAGNOSTIC (Block 2 - Inside Except): dir(ComplianceCheckStatus) after error: {dir(ComplianceCheckStatus)}")
                 logger_nodes.error(f"DIAGNOSTIC (Block 2): ComplianceCheckStatus at error: ID: {id(ComplianceCheckStatus)}, Type: {type(ComplianceCheckStatus)}")
                 raise

        logger_nodes.info(f"DIAGNOSTIC (2): Type of ComplianceCheckStatus: {type(ComplianceCheckStatus)}")
        logger_nodes.info(f"DIAGNOSTIC (2): Members of ComplianceCheckStatus: {[member.name for member in ComplianceCheckStatus]}")

        # Prepare evidence list by ensuring all components are strings
        final_evidence_strings: List[str] = []
        
        # Process supporting_documentation
        for item in (supporting_documentation or []):
            if not isinstance(item, str):
                logger_nodes.warning(f"Item in supporting_documentation is not a string (type: {type(item)}). Converting to string: {str(item)[:100]}...")
                final_evidence_strings.append(str(item))
            else:
                final_evidence_strings.append(item)
        
        # Process code_references
        for item in (code_references or []):
            if not isinstance(item, str):
                logger_nodes.warning(f"Item in code_references is not a string (type: {type(item)}). Converting to string: {str(item)[:100]}...")
                final_evidence_strings.append(str(item))
            else:
                final_evidence_strings.append(item)
        
        evidence_list = final_evidence_strings # Use the explicitly stringified list

        # Prepare details string
        details_parts = []
        if evidence_summary:
            details_parts.append(evidence_summary.strip())
        # Add the suggestion previously in suggestions_for_improvement
        details_parts.append("Further review may be needed based on findings.")
        details_str = " ".join(details_parts).strip()
        if not details_str: # Ensure details is None if empty, not an empty string
            details_str = None

        # Prepare relevant_risk_tiers list from criterion_model
        model_relevant_tiers = []
        if hasattr(criterion_model, 'relevant_risk_tiers') and criterion_model.relevant_risk_tiers:
            for tier_str in criterion_model.relevant_risk_tiers:
                try:
                    # Assuming RiskTier enum members are uppercase, e.g., RiskTier.HIGH
                    model_relevant_tiers.append(RiskTier[tier_str.strip().upper()])
                except KeyError:
                    logger_nodes.warning(f"Unknown risk tier string '{tier_str}' in criterion '{criterion_id}' relevant_risk_tiers. Skipping.")
                    local_error_messages.append(f"Unknown risk tier string '{tier_str}' for criterion '{criterion_id}'.")

        # Create the checklist item
        checklist_item = ComplianceChecklistItem(
            id=criterion_id,  # Changed from criterion_id
            criterion=criterion_title,  # Changed from criterion_text
            description=criterion_model.description,
            status=current_status,
            evidence=evidence_list, # Consolidated field
            details=details_str, # Consolidated field
            relevant_risk_tiers=model_relevant_tiers # Populated from criterion_model
            # llm_assessment_prompt is optional and not set here by default
        )
        checklist.append(checklist_item)
        added_criterion_ids.add(criterion_id)
        logger_nodes.info(f"Added criterion '{criterion_id}' to checklist. Status: {current_status}")

    logger_nodes.info(f"Generated compliance checklist with {len(checklist)} items.")
    return {"compliance_checklist": checklist, "error_messages": local_error_messages}


async def prepare_final_response_node(state: ScanGraphState) -> dict:
    logger_nodes.info("--- Executing prepare_final_response_node ---")
    logger_nodes.info(f"prepare_final_response_node: state.risk_tier is {state.risk_tier} (type: {type(state.risk_tier)})") # ADDED LOG
    logger_nodes.info(f"prepare_final_response_node: state.compliance_checklist length is {len(state.compliance_checklist if state.compliance_checklist else [])}") # ADDED LOG
    logger_nodes.info(f"prepare_final_response_node: state.risk_classification_justification is '{state.risk_classification_justification}'") # ADDED LOG

    # Comprehensive initial state logging
    logger_nodes.info(f"prepare_final_response_node initial state: scan_id='{state.scan_id}'")
    logger_nodes.info(f"prepare_final_response_node initial state: risk_tier='{state.risk_tier}' (type: {type(state.risk_tier)})")
    if state.compliance_checklist:
        logger_nodes.info(f"prepare_final_response_node initial state: compliance_checklist length={len(state.compliance_checklist)}, first_item_type={type(state.compliance_checklist[0]) if state.compliance_checklist else 'N/A'}")
        # Log details of the first checklist item's relevant_risk_tiers for debugging
        if state.compliance_checklist and isinstance(state.compliance_checklist[0], ComplianceChecklistItem):
            first_item_tiers = state.compliance_checklist[0].relevant_risk_tiers
            logger_nodes.info(f"prepare_final_response_node initial state: first checklist item relevant_risk_tiers='{[tier.value for tier in first_item_tiers]}' (type: {type(first_item_tiers)})")
    else:
        logger_nodes.info("prepare_final_response_node initial state: compliance_checklist is None or empty")
    if state.doc_summary:
        logger_nodes.info(f"prepare_final_response_node initial state: doc_summary length={len(state.doc_summary)}, first_item_type={type(state.doc_summary[0]) if state.doc_summary else 'N/A'}")
    else:
        logger_nodes.info("prepare_final_response_node initial state: doc_summary is None or empty")
    logger_nodes.info(f"prepare_final_response_node initial state: risk_classification_justification='{state.risk_classification_justification}'")
    logger_nodes.info(f"prepare_final_response_node initial state: code_analysis_score='{state.code_analysis_score}'")
    if state.detailed_code_violations:
        logger_nodes.info(f"prepare_final_response_node initial state: detailed_code_violations length={len(state.detailed_code_violations)}, first_item_type={type(state.detailed_code_violations[0]) if state.detailed_code_violations else 'N/A'}")
    else:
        logger_nodes.info("prepare_final_response_node initial state: detailed_code_violations is None or empty")
    logger_nodes.info(f"prepare_final_response_node initial state: error_messages='{state.error_messages}'")

    # Ensure default values if parts of the state are not populated
    scan_id = state.scan_id or "unknown_scan_id"
    repo_url = state.input_model.repo_url if state.input_model else "unknown_repo_url"
    
    risk_tier_to_assign = state.risk_tier or RiskTier.UNKNOWN # Default if not set
    checklist_to_assign = state.compliance_checklist if state.compliance_checklist is not None else []
    doc_summary_to_assign = state.doc_summary if state.doc_summary is not None else []
    risk_justification_to_assign = state.risk_classification_justification or "Justification not available."
    code_analysis_score_to_assign = state.code_analysis_score if state.code_analysis_score is not None else 0.0
    detailed_code_violations_to_assign = state.detailed_code_violations if state.detailed_code_violations is not None else []
    error_messages_to_assign = list(state.error_messages or [])

    # Construct a more meaningful overall summary
    overall_summary = f"Scan completed for {repo_url}. "
    overall_summary += f"The system has been preliminarily classified as {risk_tier_to_assign.value} risk. "
    if risk_justification_to_assign not in ["Justification not available.", "No documentation provided for analysis.", "Classification failed or pending.", "Could not parse LLM response accurately."] and not risk_justification_to_assign.startswith("LLM initialization failed") and not risk_justification_to_assign.startswith("An error occurred during classification"):
        overall_summary += f"Justification: {risk_justification_to_assign} "
    overall_summary += f"Code analysis score: {code_analysis_score_to_assign:.2f}."

    final_response = APIScanResponse(
        scan_id=scan_id,
        overall_summary=overall_summary, # Updated placeholder text
        tier=risk_tier_to_assign, # Ensure this uses the processed value and correct field name
        checklist=checklist_to_assign, # Ensure this uses the processed value
        doc_summary=doc_summary_to_assign, # Ensure this uses the processed value
        risk_classification_justification=risk_justification_to_assign, # Added field
        code_analysis_score=code_analysis_score_to_assign, 
        detailed_code_violations=detailed_code_violations_to_assign,
        recommendations=[], # Placeholder
        timestamp=datetime.utcnow().isoformat(),
        error_messages=error_messages_to_assign
    )
    logger_nodes.info(f"Prepared final response model: {final_response.model_dump_json(indent=2)}")
    return {"final_api_response": final_response, "error_messages": error_messages_to_assign}


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

    repo_url_str = None
    repo_owner_str = None
    repo_name_str = None

    # Prioritize repo_info from the cloning/download step if available
    if state.repo_info:
        repo_owner_str = state.repo_info.owner
        repo_name_str = state.repo_info.repo
        if state.repo_info.owner and state.repo_info.repo:
            # Construct URL if not directly available from input_model, assuming GitHub
            repo_url_str = f"https://github.com/{state.repo_info.owner}/{state.repo_info.repo}"
        if state.input_model and state.input_model.repo_url: # Prefer explicit input URL if provided
             repo_url_str = str(state.input_model.repo_url)

    # Fallback to input_model if repo_info wasn't fully populated or available
    if not repo_owner_str or not repo_name_str:
        if state.input_model:
            if state.input_model.repo_url and not repo_url_str: # Set repo_url_str if not already set
                repo_url_str = str(state.input_model.repo_url)
            
            if state.input_model.repo_details: # If explicit details are given
                repo_owner_str = state.input_model.repo_details.owner
                repo_name_str = state.input_model.repo_details.repo
                if not repo_url_str and repo_owner_str and repo_name_str: # Construct URL if needed
                    repo_url_str = f"https://github.com/{repo_owner_str}/{repo_name_str}"
            elif repo_url_str: # Try to parse from URL if no explicit details
                try:
                    parsed_url = urlparse(repo_url_str)
                    path_parts = parsed_url.path.strip('/').split('/')
                    if len(path_parts) >= 2 and parsed_url.hostname == "github.com":
                        repo_owner_str = path_parts[0]
                        repo_name_str = path_parts[1].replace('.git', '')
                except Exception as e:
                    logger_nodes.warning(f"Could not parse owner/repo from repo_url '{repo_url_str}': {e}")

    # Ensure repo_url_str has a default if still None
    if not repo_url_str:
        repo_url_str = "unknown_repo_url"

    # Determine user_id (currently not in RepoInputModel, so defaults to anonymous)
    # If user_id were added to RepoInputModel: user_id = state.input_model.user_id if state.input_model and hasattr(state.input_model, 'user_id') else "anonymous"
    user_id_str = "anonymous" # Placeholder until user_id is properly sourced

    try:
        persistence_data = ScanPersistenceData(
            scan_id=state.scan_id, # Now a field in ScanPersistenceData
            user_id=user_id_str, # Now a field in ScanPersistenceData
            status="completed", # Now a field in ScanPersistenceData, assuming completion
            repo_url=repo_url_str if repo_url_str else "unknown_repo_url",
            repo_owner=repo_owner_str,
            repo_name=repo_name_str,
            commit_sha=state.commit_sha,
            scan_timestamp=state.final_api_response.timestamp if state.final_api_response.timestamp else datetime.utcnow(),
            risk_tier=state.risk_tier,
            risk_classification_justification=state.risk_classification_justification,
            code_analysis_score=state.code_analysis_score,
            checklist=state.compliance_checklist, # Added checklist
            doc_summary=state.doc_summary, # Added doc_summary
            final_response_json=state.final_api_response.model_dump() if state.final_api_response else None, # Now a field
            error_messages=state.error_messages if state.error_messages else []
        )

        logger_nodes.info(f"Prepared data for persistence: {persistence_data.model_dump_json(indent=2)}")
        logger_nodes.info(f"Prepared data for persistence: {persistence_data.model_dump_json(indent=2)}")

        # Placeholder for actual database interaction
        logger_nodes.warning("Actual persistence logic (database save) is still a placeholder.")
        # Example of what would happen here:
        # async with get_db_session() as db_session:
        #     await crud_scan_record.create_or_update_scan_persistence_data(db_session, persistence_data)
        
        # For now, we can store it in the state if that's useful for testing or if no DB is connected
        # state.persistence_data = persistence_data # Corrected attribute name to match ScanGraphState

    except Exception as e:
        error_msg = f"Error preparing/persisting data: {e}"
        logger_nodes.error(error_msg, exc_info=True)
        # It's crucial to return a dict that includes 'error_messages' for graph state update
        current_errors = list(state.error_messages or [])
        current_errors.append(error_msg)
        return {"error_messages": current_errors, "persistence_data": None} # Ensure all expected keys are present if node modifies them

    # If successful, ensure persistence_data is part of the output if the graph expects it
    # And ensure error_messages reflects the current state (empty if no new errors)
    return {
        "persistence_data": persistence_data,
        "risk_tier": state.risk_tier,
        "compliance_checklist": state.compliance_checklist,
        "doc_summary": state.doc_summary,
        "final_api_response": state.final_api_response,
        "risk_classification_justification": state.risk_classification_justification,
        "code_analysis_score": state.code_analysis_score,
        "detailed_code_violations": state.detailed_code_violations,
        "error_messages": list(state.error_messages or [])
    }

# Graph definition
