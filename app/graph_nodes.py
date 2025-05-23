# app/graph_nodes.py

from typing import Dict, Any, Optional, List, Tuple
from .models import RepoInputModel, ScanGraphState, RepoInfo, CodeAnalysisResult, CodeSignal, RiskTier, APIScanResponse, ScanPersistenceData # Import APIScanResponse and ScanPersistenceData
from .scanner import resolve_repo_input # Assuming resolve_repo_input can be imported
import tempfile
import shutil
import os
import asyncio
from .utils import get_repo_archive_info, download_repo_zip, unzip_archive, find_documentation_files, find_code_files, extract_text_and_headings_from_markdown, parse_openapi_file # Keep other utils imports
from .config import settings
from .logger import get_logger # Revert to get_logger from .logger
from .services.llm_service import LLMService # Import LLMService
import ast
from app.crud import create_scan_record # Import create_scan_record
from app.db.session import async_session_factory # Import session maker for creating database sessions

logger_nodes = get_logger(__name__) # Revert to get_logger(__name__)

# --- Sensitive Library Definitions for AST Analysis ---
SENSITIVE_LIBRARIES_CONFIG = {
    "biometric": ["face_recognition", "cv2", "dlib", "mediapipe"], # cv2 is OpenCV import name
    "live_stream": ["websockets", "socketio", "aiohttp", "kafka", "pika", "rtsp", "webrtc"], # kafka-python often 'kafka'
    "gpai": ["transformers", "tensorflow", "torch", "keras", "openai", "anthropic", "langchain", "google.generativeai"]
}

ALL_SENSITIVE_IMPORTS = list(set([lib for sublist in SENSITIVE_LIBRARIES_CONFIG.values() for lib in sublist]))
# --- End Sensitive Library Definitions ---


class PythonAstAnalyzer(ast.NodeVisitor):
    """Visits AST nodes to find imported modules."""
    def __init__(self):
        self.imported_modules = set()

    def visit_Import(self, node):
        for alias in node.names:
            # Add the root module (e.g., 'os.path' becomes 'os')
            self.imported_modules.add(alias.name.split('.')[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            # Add the root module (e.g., 'collections.abc' becomes 'collections')
            self.imported_modules.add(node.module.split('.')[0])
        # For 'from . import foo' or 'from ..bar import baz', node.module is None or starts with .
        # These are relative imports, less likely to be top-level sensitive libraries directly,
        # but good to be aware of. For now, we focus on top-level external libs.
        self.generic_visit(node)

    def get_imported_modules(self) -> List[str]:
        return sorted(list(self.imported_modules))


def _analyze_single_python_file(py_file_path: str) -> Tuple[str, CodeAnalysisResult, Optional[str]]:
    """Synchronous helper to analyze a single Python file. Returns (file_path, result, error_message)."""
    try:
        logger_nodes.debug(f"Starting AST analysis for: {py_file_path}")
        with open(py_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content, filename=py_file_path)
        analyzer = PythonAstAnalyzer()
        analyzer.visit(tree)
        imported_modules_in_file = analyzer.get_imported_modules()
        
        result = CodeAnalysisResult(
            file_path=py_file_path,
            imported_modules=imported_modules_in_file
        )
        logger_nodes.debug(f"Finished AST analysis for: {py_file_path}, imports: {imported_modules_in_file}")
        return py_file_path, result, None
    except SyntaxError as e_syn:
        error_msg = f"SyntaxError analyzing {py_file_path}: {e_syn}"
        logger_nodes.warning(error_msg)
        # Store a basic result indicating error for this file
        result = CodeAnalysisResult(
            file_path=py_file_path,
            imported_modules=[f"SYNTAX_ERROR: {e_syn}"]
        )
        return py_file_path, result, error_msg
    except Exception as e:
        error_msg = f"Error analyzing Python file {py_file_path}: {e}"
        logger_nodes.error(f"{error_msg} - in _analyze_single_python_file", exc_info=True)
        result = CodeAnalysisResult(
            file_path=py_file_path,
            imported_modules=[f"ANALYSIS_ERROR: {e}"]
        )
        return py_file_path, result, error_msg

async def initial_setup_node(state: ScanGraphState) -> Dict[str, Any]:
    """Populates initial repository information in the graph state."""
    print("--- Executing InitialSetupNode ---")
    input_model = state.input_model
    repo_info: Optional[RepoInfo] = state.repo_info

    if not repo_info:
        if input_model.repo_details:
            # If repo_details are directly in input_model, use them
            repo_info = input_model.repo_details
        elif input_model.repo_url:
            # If only repo_url is in input_model, create a temporary RepoInputModel
            # instance to pass to resolve_repo_input, or directly use it if resolve_repo_input
            # can handle just the URL part of RepoInputModel.
            # The current resolve_repo_input expects a full RepoInputModel.
            temp_input_for_resolution = RepoInputModel(repo_url=input_model.repo_url)
            try:
                repo_info = await resolve_repo_input(temp_input_for_resolution)
            except ValueError as e:
                print(f"InitialSetupNode: Error resolving repo_input from URL: {e}")
                return {"error_messages": state.error_messages + [f"Failed to resolve repository from URL: {e}"]}
        else:
            # This case should ideally be caught by input validation earlier
            print("InitialSetupNode: Insufficient input to determine repository details.")
            return {"error_messages": state.error_messages + ["Insufficient input to determine repository details."]}

    updated_state: Dict[str, Any] = {
        "input_model": input_model, # Ensure it's part of the returned state update
        "repo_info": repo_info,
        "error_messages": state.error_messages # carry over any existing errors
    }

    if not repo_info:
        print("InitialSetupNode: Failed to resolve repo_info")
        # Append error message if not already set by a more specific error
        if not any("Failed to resolve repository" in msg for msg in updated_state.get("error_messages", [])):
            updated_state["error_messages"] = updated_state.get("error_messages", []) + ["Failed to resolve repository details in InitialSetupNode."]
    else:
        print(f"InitialSetupNode: Resolved repo_info: {repo_info.owner}/{repo_info.repo} branch: {repo_info.branch}")

    return updated_state

async def download_and_unzip_repo_node(state: ScanGraphState) -> Dict[str, Any]:
    """Downloads the repository ZIP and unzips it into a temporary directory."""
    logger_nodes.info("--- Executing DownloadAndUnzipRepoNode ---")
    repo_info = state.repo_info
    error_messages = list(state.error_messages) # Make a mutable copy

    if not repo_info:
        error_messages.append("Repository information is missing, cannot download.")
        logger_nodes.error("DownloadAndUnzipRepoNode: RepoInfo missing.")
        return {"error_messages": error_messages}

    temp_dir = None
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="repo_scan_")
        logger_nodes.info(f"Created temporary directory: {temp_dir}")

        # 1. Get repository archive info (target branch and commit SHA)
        logger_nodes.info(f"Fetching archive info for {repo_info.owner}/{repo_info.repo} (branch: {repo_info.branch})")
        # get_repo_archive_info now returns (target_branch_name, commit_sha)
        target_branch, actual_commit_sha = await get_repo_archive_info(
            state.repo_info, # Pass the full RepoInfo object
            settings.GITHUB_TOKEN
        )
        logger_nodes.info(f"Got target branch: {target_branch}, Commit SHA: {actual_commit_sha}")

        # Construct the zipball URL using the commit SHA for precision
        # This zip_url is for logging/reference; download_repo_zip will construct its own based on commit_sha
        constructed_zip_url_for_reference = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}/zipball/{actual_commit_sha}"
        logger_nodes.info(f"Reference archive URL: {constructed_zip_url_for_reference}")

        # 2. Download the repository zip file
        # The download_repo_zip function handles the creation of the zip_url and filename internally.
        # It expects RepoInfo, commit_sha/branch, token, and download_dir.
        logger_nodes.info(f"Downloading repository to {temp_dir} using commit SHA {actual_commit_sha}...")
        zip_file_path = await download_repo_zip(
            repo_info=state.repo_info, 
            commit_sha_or_branch=actual_commit_sha, 
            token=settings.GITHUB_TOKEN, 
            download_dir=temp_dir
        )
        logger_nodes.info(f"Repository downloaded successfully to {zip_file_path}.")

        # 3. Unzip the archive
        logger_nodes.info(f"Unzipping archive {zip_file_path} to {temp_dir}...")
        # unzip_archive returns the path to the *actual content directory* within temp_dir
        unzipped_content_path = await unzip_archive(zip_file_path, temp_dir) 
        logger_nodes.info(f"Repository unzipped successfully to {unzipped_content_path}.")

        # Clean up the downloaded zip file as it's no longer needed
        try:
            os.remove(zip_file_path)
            logger_nodes.info(f"Cleaned up downloaded zip file: {zip_file_path}")
        except OSError as e:
            logger_nodes.warning(f"Could not remove zip file {zip_file_path}: {e}")

        # Update state with paths and commit SHA
        # Note: temp_dir is the parent temporary directory created at the start.
        # unzipped_content_path is the actual path to the repository's root contents.
        return {
            "temp_repo_path": unzipped_content_path, # This is the path to the unzipped repo code
            "commit_sha": actual_commit_sha,
            "repo_download_url": constructed_zip_url_for_reference, 
            "error_messages": error_messages 
        }

    except Exception as e:
        logger_nodes.error(f"Error in DownloadAndUnzipRepoNode: {e}", exc_info=True)
        error_messages.append(f"Failed to download or unzip repository: {str(e)}")
        # Clean up temp_dir if it was created and an error occurred
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger_nodes.info(f"Cleaned up temporary directory {temp_dir} after error.")
            except Exception as cleanup_e:
                logger_nodes.error(f"Error cleaning up temp_dir {temp_dir}: {cleanup_e}")
        return {"temp_repo_path": None, "error_messages": error_messages}
    # Note: Successful cleanup of temp_dir should happen at the end of the entire graph execution.
    # Storing temp_dir_path in the state allows a final node to handle this.


async def discover_files_node(state: ScanGraphState) -> dict:
    """Scans the unzipped repository to discover relevant files (documentation, code)."""
    logger_nodes.info("--- Executing DiscoverFilesNode ---")
    if not state.temp_repo_path or not os.path.exists(state.temp_repo_path):
        logger_nodes.error("Temporary repository path not found or invalid.")
        return {"error_messages": state.error_messages + ["Temporary repository path not found for file discovery."]}

    discovered_docs = {}
    discovered_code = {}
    error_messages = list(state.error_messages) # Make a mutable copy

    try:
        logger_nodes.info(f"Discovering documentation files in {state.temp_repo_path}...")
        # Run synchronous glob operations in a separate thread
        discovered_docs = await asyncio.to_thread(find_documentation_files, state.temp_repo_path)
        for file_type, files in discovered_docs.items():
            logger_nodes.info(f"Found {len(files)} {file_type} files.")

        logger_nodes.info(f"Discovering code files in {state.temp_repo_path}...")
        # Run synchronous glob operations in a separate thread
        discovered_code = await asyncio.to_thread(find_code_files, state.temp_repo_path)
        for file_type, files in discovered_code.items():
            logger_nodes.info(f"Found {len(files)} {file_type} code files.")

    except Exception as e:
        error_msg = f"Error during file discovery: {e}"
        logger_nodes.error(error_msg, exc_info=True)
        error_messages.append(error_msg)
        # Return current state of discovered files even if one part fails
        # and include the error message.

    # Merge discovered files into the state's discovered_files dictionary
    # Ensure we don't overwrite existing keys if this node were to be run multiple times
    # or if other nodes also contribute to discovered_files (though not currently the case).
    updated_discovered_files = state.discovered_files.copy() # Start with existing
    updated_discovered_files.update(discovered_docs)         # Add/overwrite doc files
    updated_discovered_files.update(discovered_code)         # Add/overwrite code files

    logger_nodes.info(f"File discovery complete. Total discovered file categories: {len(updated_discovered_files)}")
    
    return {
        "discovered_files": updated_discovered_files,
        "error_messages": error_messages
    }


async def process_discovered_files_node(state: ScanGraphState) -> dict:
    """Reads and parses discovered documentation files (Markdown, OpenAPI)."""
    logger_nodes.info("--- Executing ProcessDiscoveredFilesNode ---")

    # Initialize from current state or defaults
    file_content_cache = state.file_content_cache.copy()
    extracted_markdown_docs = list(state.extracted_markdown_docs)
    parsed_openapi_specs = list(state.parsed_openapi_specs)
    error_messages = list(state.error_messages)

    # Process Markdown files
    markdown_files = state.discovered_files.get('markdown', [])
    if markdown_files:
        logger_nodes.info(f"Processing {len(markdown_files)} Markdown files...")
        for md_file_path in markdown_files:
            try:
                with open(md_file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                file_content_cache[md_file_path] = content
                
                text, headings = extract_text_and_headings_from_markdown(md_file_path)
                # Append as a tuple to match ScanGraphState model definition
                extracted_markdown_docs.append((md_file_path, text, headings))
                logger_nodes.info(f"Successfully processed Markdown/RST: {md_file_path}")
            except Exception as e:
                error_msg = f"Error processing Markdown/RST file {md_file_path}: {e}"
                logger_nodes.error(error_msg, exc_info=True)
                error_messages.append(error_msg)
    else:
        logger_nodes.info("No Markdown files to process.")

    # Process OpenAPI files
    openapi_files = state.discovered_files.get('openapi', [])
    if openapi_files:
        logger_nodes.info(f"Processing {len(openapi_files)} OpenAPI/Swagger files...")
        for spec_file_path in openapi_files:
            try:
                # parse_openapi_file reads the file itself
                parsed_spec = parse_openapi_file(spec_file_path)
                if parsed_spec:
                    # Cache the raw content if successfully parsed (or attempt to read for cache)
                    try:
                        with open(spec_file_path, 'r', encoding='utf-8') as f:
                            file_content_cache[spec_file_path] = f.read()
                    except Exception as e_read:
                        logger_nodes.warning(f"Could not cache content for OpenAPI spec {spec_file_path}: {e_read}")

                    # Append as a tuple to match ScanGraphState model definition
                    parsed_openapi_specs.append((spec_file_path, parsed_spec))
                    logger_nodes.info(f"Successfully parsed OpenAPI/Swagger: {spec_file_path}")
                else:
                    logger_nodes.warning(f"File {spec_file_path} was not recognized as a valid OpenAPI/Swagger spec or parsing failed.")
            except Exception as e:
                error_msg = f"Error processing OpenAPI/Swagger file {spec_file_path}: {e}"
                logger_nodes.error(error_msg, exc_info=True)
                error_messages.append(error_msg)
    else:
        logger_nodes.info("No OpenAPI/Swagger files to process.")

    logger_nodes.info("File processing complete.")

    return {
        "file_content_cache": file_content_cache,
        "extracted_markdown_docs": extracted_markdown_docs,
        "parsed_openapi_specs": parsed_openapi_specs,
        "error_messages": error_messages
    }


async def analyze_python_code_node(state: ScanGraphState) -> dict:
    """Analyzes discovered Python files using AST to find imports and identify sensitive library usage."""
    logger_nodes.info("--- Executing AnalyzePythonCodeNode ---")

    analysis_results_dict: Dict[str, CodeAnalysisResult] = {}
    aggregated_signals = CodeSignal() # Initialize with defaults
    error_messages = list(state.error_messages) # Preserve existing errors

    python_files = state.discovered_files.get('python', [])
    if not python_files:
        logger_nodes.info("No Python files to analyze.")
        return {
            "code_ast_analysis_results": analysis_results_dict,
            "aggregated_code_signals": aggregated_signals,
            "error_messages": error_messages
        }

    logger_nodes.info(f"Analyzing {len(python_files)} Python files using asyncio.to_thread...")

    tasks = [_analyze_single_python_file(py_file_path) for py_file_path in python_files]
    # Run analysis for all files concurrently in threads
    # Note: asyncio.to_thread is for a single blocking function. 
    # To run multiple, we wrap them or use a loop with asyncio.create_task(asyncio.to_thread(...))
    # Or, more simply, use asyncio.gather with to_thread for each call.
    
    thread_results = await asyncio.gather(*[asyncio.to_thread(_analyze_single_python_file, fp) for fp in python_files])

    for file_path, single_file_result, error_msg in thread_results:
        analysis_results_dict[file_path] = single_file_result
        if error_msg:
            error_messages.append(error_msg)
        
        # Update aggregated signals from successfully parsed files
        if not error_msg: # Only process if _analyze_single_python_file reported no error for this file
            for imported_module in single_file_result.imported_modules:
                if imported_module in ALL_SENSITIVE_IMPORTS and imported_module not in aggregated_signals.detected_libraries:
                    aggregated_signals.detected_libraries.append(imported_module)
                
                if imported_module in SENSITIVE_LIBRARIES_CONFIG["biometric"]:
                    aggregated_signals.biometric = True
                if imported_module in SENSITIVE_LIBRARIES_CONFIG["live_stream"]:
                    aggregated_signals.live_stream = True
                if imported_module in SENSITIVE_LIBRARIES_CONFIG["gpai"]:
                    aggregated_signals.uses_gpai = True
    
    aggregated_signals.detected_libraries.sort()
    logger_nodes.info(f"Python code analysis complete. Aggregated signals: {aggregated_signals.model_dump_json(indent=2)}")

    return {
        "code_ast_analysis_results": analysis_results_dict,
        "aggregated_code_signals": aggregated_signals,
        "error_messages": error_messages
    }


async def summarize_documentation_node(state: ScanGraphState) -> dict:
    """Summarizes extracted documentation using an LLM."""
    logger_nodes.info("--- Executing SummarizeDocumentationNode ---")
    error_messages = list(state.error_messages) # Preserve existing errors
    doc_summary_points: Optional[List[str]] = None

    # Consolidate markdown text and headings
    full_markdown_text = "\n\n---\n\n".join([doc[1] for doc in state.extracted_markdown_docs]) # Use doc[1] for content
    all_headings = []
    for doc in state.extracted_markdown_docs:
        all_headings.extend(doc[2]) # Use doc[2] for headings
    
    # Prepare OpenAPI spec summaries (currently storing full parsed dict, might need adjustment if LLMService expects simpler summary)
    # For now, _construct_llm_prompt_for_doc_summary in LLMService seems to handle the dict.
    openapi_specs_for_llm = [spec_data for _, spec_data in state.parsed_openapi_specs]

    if not full_markdown_text and not openapi_specs_for_llm:
        logger_nodes.info("No documentation content (Markdown or OpenAPI) found to summarize.")
        return {"doc_summary": ["Information: No textual documentation or API specs found to summarize."], "error_messages": error_messages}

    llm_service = LLMService()
    if not llm_service.aclient: # Check if client initialized (API key might be missing)
        error_msg = "LLMService client not initialized, likely missing OpenAI API key."
        logger_nodes.error(error_msg)
        error_messages.append(error_msg)
        return {"doc_summary": [f"Error: {error_msg}"], "error_messages": error_messages}

    try:
        logger_nodes.info(f"Requesting summary from LLMService for {len(state.extracted_markdown_docs)} MD docs and {len(openapi_specs_for_llm)} OpenAPI specs.")
        doc_summary_points = await llm_service.get_llm_summary(
            markdown_text=full_markdown_text,
            headings=all_headings,
            openapi_specs=openapi_specs_for_llm,
            model_name=settings.OPENAI_MODEL_NAME # Use model from config
        )
        if doc_summary_points:
            logger_nodes.info(f"LLM summary received: {len(doc_summary_points)} bullet points.")
        else:
            # get_llm_summary should return a list with an error/warning if it fails internally
            # but as a fallback if it returns None (e.g. unexpected exception)
            error_msg = "LLM summarization returned no result."
            logger_nodes.warning(error_msg)
            doc_summary_points = [f"Warning: {error_msg}"]
            error_messages.append(error_msg)
            
    except Exception as e:
        error_msg = f"Error during LLM summarization: {e}"
        logger_nodes.error(error_msg, exc_info=True)
        doc_summary_points = [f"Error: {error_msg}"]
        error_messages.append(error_msg)

    return {
        "doc_summary": doc_summary_points,
        "error_messages": error_messages
    }


# --- Rule Engine Helper for Risk Classification ---
def _apply_risk_classification_rules(
    doc_summary: Optional[List[str]],
    code_signals: Optional[CodeSignal]
) -> Optional[RiskTier]:
    """
    Applies a set of rules to classify risk based on documentation summary and code signals.
    Returns a RiskTier or None if no rule confidently matches.
    """
    if not doc_summary and not code_signals:
        logger_nodes.info("Not enough information for rule-based risk classification.")
        return None

    summary_text = " ".join(doc_summary).lower() if doc_summary else ""
    
    # --- Prohibited Risk Rules ---
    prohibited_keywords_details = {
        "social scoring by public authorities": "Social scoring by public authorities.",
        "real-time remote biometric identification in public spaces for law enforcement": "Real-time remote biometric ID for law enforcement (requires biometric signal).",
        "subliminal techniques": "Subliminal techniques to distort behavior.",
        "manipulative ai": "Manipulative or deceptive AI techniques.",
        "exploiting vulnerabilities": "Exploiting vulnerabilities of specific groups."
    }
    for keyword, reason in prohibited_keywords_details.items():
        if keyword in summary_text:
            if keyword == "real-time remote biometric identification in public spaces for law enforcement":
                if code_signals and code_signals.biometric:
                    logger_nodes.info(f"Rule matched: Prohibited ({reason})")
                    return RiskTier.PROHIBITED
            else:
                logger_nodes.info(f"Rule matched: Prohibited ({reason})")
                return RiskTier.PROHIBITED

    # --- High Risk Rules ---
    # Keywords associated with high-risk AI systems when GPAI is involved
    high_risk_gpai_keywords_details = {
        "critical infrastructure": "GPAI in critical infrastructure (e.g., transport, energy).",
        "educational assessment": "GPAI in educational/vocational training assessment.",
        "vocational training": "GPAI in educational/vocational training access.",
        "employment management": "GPAI in employment, worker management, recruitment.",
        "recruitment": "GPAI in recruitment processes.",
        "worker management": "GPAI in worker management.",
        "access to essential services": "GPAI for access to essential public/private services (e.g., welfare).",
        "credit scoring": "GPAI in credit scoring.",
        "welfare allocation": "GPAI in welfare benefit allocation.",
        "law enforcement risk assessment": "GPAI for risk assessment in law enforcement.",
        "polygraph": "GPAI used as or in polygraphs/lie detectors.",
        "migration management": "GPAI in migration, asylum, border control.",
        "asylum processing": "GPAI in asylum processing.",
        "border control": "GPAI in border control management.",
        "administration of justice": "GPAI in administration of justice.",
        "democratic process": "GPAI influencing democratic processes."
    }
    if code_signals and code_signals.uses_gpai:
        for keyword, reason in high_risk_gpai_keywords_details.items():
            if keyword in summary_text:
                logger_nodes.info(f"Rule matched: High Risk ({reason})")
                return RiskTier.HIGH

    # Biometric systems (broader than prohibited category)
    if code_signals and code_signals.biometric:
        if "biometric identification" in summary_text or "facial recognition" in summary_text or "emotion recognition" in summary_text:
            # Check if it's not already Prohibited (more specific Prohibited rule for biometrics exists)
            # This is a simplification; the act has specific categories for high-risk biometrics.
            logger_nodes.info("Rule matched: High Risk (Biometric identification/categorization system).")
            return RiskTier.HIGH
            
    # --- Limited Risk Rules (Example) ---
    # If uses GPAI, interacts with humans, and not caught by High/Prohibited rules.
    # This is a broad simplification for systems like general chatbots or AI content generators.
    if code_signals and code_signals.uses_gpai:
        if "chatbot" in summary_text or "generative ai" in summary_text or "generates content" in summary_text or "ai assistant" in summary_text:
            # This rule should be evaluated after Prohibited and High risk checks for GPAI.
            # If a GPAI system is for a high-risk purpose, it's High, not Limited.
            logger_nodes.info("Rule matched: Limited Risk (Interactive GPAI system, e.g., chatbot, content generation, subject to transparency).")
            return RiskTier.LIMITED
        
    # --- Minimal Risk (Default if some info exists but no specific rules matched) ---
    if doc_summary or (code_signals and (code_signals.biometric or code_signals.live_stream or code_signals.uses_gpai or code_signals.detected_libraries)):
        # Only classify as minimal if there was *some* indication of AI/data processing, but it didn't hit higher tiers.
        # If no info at all, we should probably return None/Unknown.
        logger_nodes.info("Rule matched: Minimal Risk (AI system, but no specific high-impact indicators found by rules).")
        return RiskTier.MINIMAL

    logger_nodes.info("No specific rules matched confidently for risk classification.")
    return None # Triggers LLM fallback or sets to UNKNOWN


async def classify_risk_tier_node(state: ScanGraphState) -> dict:
    """Classifies the repository's AI risk tier based on rules and LLM fallback."""
    logger_nodes.info("--- Executing ClassifyRiskTierNode ---")
    error_messages = list(state.error_messages)
    determined_tier: Optional[RiskTier] = None

    # 1. Apply Rule-Based Classification
    if state.doc_summary is None and state.aggregated_code_signals is None:
        logger_nodes.info("No document summary or code signals available for risk classification.")
        determined_tier = RiskTier.UNKNOWN
    else:
        determined_tier = _apply_risk_classification_rules(
            state.doc_summary,
            state.aggregated_code_signals
        )

    # 2. LLM Fallback (if rules are not conclusive or no info for rules)
    if determined_tier is None: # This means rules were inconclusive
        logger_nodes.info("Rule-based classification inconclusive or insufficient info. Attempting LLM fallback.")
        llm_service = LLMService()
        if llm_service.aclient:
            try:
                llm_classified_tier_str = await llm_service.classify_risk_with_llm(
                    state.doc_summary,
                    state.aggregated_code_signals,
                    model_name=settings.RISK_CLASSIFICATION_MODEL # Use the risk classification model from config
                )
                if llm_classified_tier_str:
                    try:
                        determined_tier = RiskTier(llm_classified_tier_str.lower())
                        logger_nodes.info(f"LLM classified risk as: {determined_tier.value}")
                    except ValueError:
                        error_msg = f"LLM returned an invalid risk tier string: '{llm_classified_tier_str}'"
                        logger_nodes.warning(error_msg)
                        error_messages.append(error_msg)
                        determined_tier = RiskTier.UNKNOWN # Fallback if LLM response is weird
                else:
                    logger_nodes.warning("LLM did not provide a classification or an error occurred internally in LLMService.")
                    # If LLMService.classify_risk_with_llm returns None (e.g. API error), it means it couldn't classify.
                    determined_tier = RiskTier.UNKNOWN
            except Exception as e:
                error_msg = f"Error during LLM risk classification call: {e}"
                logger_nodes.error(error_msg, exc_info=True)
                error_messages.append(error_msg)
                determined_tier = RiskTier.UNKNOWN
        else:
            error_msg = "LLMService client not available for risk classification fallback."
            logger_nodes.error(error_msg)
            error_messages.append(error_msg)
            determined_tier = RiskTier.UNKNOWN
        
        # If still None after LLM attempt (e.g., LLM also failed or returned UNKNOWN effectively)
        if determined_tier is None:
            logger_nodes.warning("Risk classification remains undetermined after LLM fallback. Setting to UNKNOWN.")
            determined_tier = RiskTier.UNKNOWN

    elif determined_tier == RiskTier.MINIMAL and not (state.doc_summary and any(s.strip() for s in state.doc_summary)):
        # If rules defaulted to MINIMAL but there was actually no doc summary, it's more UNKNOWN
        logger_nodes.info("Rules defaulted to Minimal, but no doc summary was present. Revising to UNKNOWN.")
        determined_tier = RiskTier.UNKNOWN

    logger_nodes.info(f"Final determined risk tier: {determined_tier.value if determined_tier else 'None'}")

    return {
        "risk_tier": determined_tier,
        "error_messages": error_messages
    }

# --- Sample Checklist Data ---
# In a real app, this would likely be loaded from a YAML/JSON file
COMPLIANCE_CHECKLISTS: Dict[RiskTier, List[Dict[str, Any]]] = {
    RiskTier.PROHIBITED: [
        {"id": "PRO-001", "title": "Cease and Desist System Operation", "description": "Systems classified as Prohibited AI are banned. All development and deployment must be halted immediately.", "category": "Operational"},
        {"id": "PRO-002", "title": "Notify Relevant Authorities", "description": "Report the existence and nature of the prohibited system to national supervisory authorities.", "category": "Legal"}
    ],
    RiskTier.HIGH: [
        {"id": "HIGH-001", "title": "Establish Risk Management System", "description": "Implement a continuous risk management system throughout the AI system's lifecycle.", "category": "Governance"},
        {"id": "HIGH-002", "title": "Data Governance and Management", "description": "Ensure training, validation, and testing data sets are relevant, representative, free of errors, and complete.", "category": "Data"},
        {"id": "HIGH-003", "title": "Technical Documentation", "description": "Draw up technical documentation before the system is placed on the market or put into service.", "category": "Documentation"},
        {"id": "HIGH-004", "title": "Record-Keeping", "description": "Ensure automatic logging of events (record-keeping) for traceability.", "category": "Operational"},
        {"id": "HIGH-005", "title": "Transparency and Provision of Information to Users", "description": "Design and develop AI systems to ensure their operation is sufficiently transparent to enable users to interpret the system's output and use it appropriately.", "category": "Transparency"},
        {"id": "HIGH-006", "title": "Human Oversight", "description": "Ensure AI systems are designed and developed to be effectively overseen by natural persons during the period the AI system is in use.", "category": "Oversight"},
        {"id": "HIGH-007", "title": "Accuracy, Robustness, and Cybersecurity", "description": "Ensure AI systems achieve an appropriate level of accuracy, robustness, and cybersecurity throughout their lifecycle.", "category": "Technical"},
        {"id": "HIGH-008", "title": "Conformity Assessment", "description": "Undergo a conformity assessment before being placed on the market or put into service.", "category": "Compliance"}
    ],
    RiskTier.LIMITED: [
        {"id": "LIM-001", "title": "Transparency Obligations", "description": "Ensure users are aware they are interacting with an AI system, unless this is obvious from the circumstances.", "category": "Transparency"},
        {"id": "LIM-002", "title": "Deepfake Disclosure", "description": "If generating or manipulating image, audio, or video content that appreciably resembles existing persons, places or events and would falsely appear to a person to be authentic (deepfakes), disclose that the content has been artificially generated or manipulated.", "category": "Transparency"}
    ],
    RiskTier.MINIMAL: [
        {"id": "MIN-001", "title": "Voluntary Codes of Conduct", "description": "Consider adhering to voluntary codes of conduct for minimal risk AI systems.", "category": "BestPractice"},
        {"id": "MIN-002", "title": "General Software Best Practices", "description": "Apply standard software development best practices, including security and quality assurance.", "category": "BestPractice"}
    ],
    RiskTier.UNKNOWN: [
        {"id": "UNK-001", "title": "Further Investigation Required", "description": "The risk tier could not be determined. Further investigation and manual assessment are required.", "category": "Assessment"}
    ]
}

async def lookup_checklist_node(state: ScanGraphState) -> dict:
    """Looks up the compliance checklist based on the determined risk tier."""
    logger_nodes.info("--- Executing LookupChecklistNode ---")
    checklist: List[Dict[str, Any]] = []
    error_messages = list(state.error_messages)

    if state.risk_tier:
        logger_nodes.info(f"Looking up checklist for risk tier: {state.risk_tier.value}")
        checklist = COMPLIANCE_CHECKLISTS.get(state.risk_tier, [])
        if not checklist and state.risk_tier != RiskTier.UNKNOWN: # UNKNOWN has its own entry
            logger_nodes.warning(f"No specific checklist found for risk tier '{state.risk_tier.value}', defaulting to empty. This might indicate a missing checklist definition.")
            # Optionally, assign a default 'further investigation' checklist if not UNKNOWN and not found
            # checklist = COMPLIANCE_CHECKLISTS.get(RiskTier.UNKNOWN, []) 
    else:
        error_msg = "Risk tier not determined, cannot look up checklist."
        logger_nodes.warning(error_msg)
        error_messages.append(error_msg)
        # Default to UNKNOWN checklist if risk_tier itself is None
        checklist = COMPLIANCE_CHECKLISTS.get(RiskTier.UNKNOWN, [])

    logger_nodes.info(f"Retrieved {len(checklist)} checklist items.")

    return {
        "checklist": checklist,
        "error_messages": error_messages
    }

async def prepare_final_response_node(state: ScanGraphState) -> dict:
    """Prepares the final API response from the graph state."""
    logger_nodes.info("--- Executing PrepareFinalResponseNode ---")
    
    # Consolidate error messages from the state if they were a list
    # In the latest ScanGraphState, error_messages is Optional[List[str]]
    current_error_messages = list(state.error_messages) if state.error_messages else []

    # If critical information is missing, it might be reflected in error_messages or an UNKNOWN tier.
    # For example, if risk_tier is None, it implies a significant failure earlier in the graph.
    if state.risk_tier is None and not any("Risk tier not determined" in msg for msg in current_error_messages):
        current_error_messages.append("Critical error: Risk tier assessment failed or was not performed.")

    final_response = APIScanResponse(
        tier=state.risk_tier,
        checklist=state.checklist,
        doc_summary=state.doc_summary,
        evidence_snippets=state.aggregated_code_signals, # Using aggregated_code_signals as evidence
        error_messages=current_error_messages if current_error_messages else None
    )
    
    logger_nodes.info(f"Final API response prepared. Tier: {final_response.tier}")
    
    return {"final_api_response": final_response, "error_messages": current_error_messages}

async def prepare_persistence_data_node(state: ScanGraphState) -> dict:
    """Prepares the data to be persisted to the database from the graph state."""
    logger_nodes.info("--- Executing PreparePersistenceDataNode ---")

    repo_url_to_persist = None
    if state.input_model.repo_url:
        repo_url_to_persist = str(state.input_model.repo_url)
    elif state.repo_info: # Fallback if direct URL not in input_model but repo_info was resolved
        repo_url_to_persist = f"https://github.com/{state.repo_info.owner}/{state.repo_info.repo}"

    repo_owner = state.repo_info.owner if state.repo_info else None
    repo_name = state.repo_info.repo if state.repo_info else None

    data_to_persist = ScanPersistenceData(
        repo_url=repo_url_to_persist,
        repo_owner=repo_owner,
        repo_name=repo_name,
        commit_sha=state.commit_sha,
        risk_tier=state.risk_tier,
        checklist=state.checklist,
        doc_summary=state.doc_summary,
        # scan_timestamp is handled by default_factory
        error_messages=state.error_messages if state.error_messages else None
    )

    logger_nodes.info(f"Data prepared for persistence. Repo: {data_to_persist.repo_url}, Tier: {data_to_persist.risk_tier}")

    return {"persistence_data": data_to_persist}

async def persist_scan_data_node(state: ScanGraphState) -> dict:
    """Persists the prepared scan data to the database."""
    logger_nodes.info("--- Executing PersistScanDataNode ---")
    persisted_id = None
    new_error_messages = []

    if state.persistence_data:
        try:
            logger_nodes.info(f"Attempting to persist data for repo: {state.persistence_data.repo_url}")
            # Create a new database session
            async with async_session_factory() as db_session:
                # Create the scan record
                scan_record = await create_scan_record(db=db_session, scan_data=state.persistence_data)
                # Commit the transaction
                await db_session.commit()
                persisted_id = scan_record.id
                logger_nodes.info(f"Scan data persisted successfully. Record ID: {persisted_id}")
        except Exception as e:
            error_msg = f"Error persisting scan data: {str(e)}"
            logger_nodes.error(error_msg, exc_info=True)
            new_error_messages.append(error_msg)
    else:
        error_msg = "Persistence data not found in state. Skipping database persistence."
        logger_nodes.warning(error_msg)
        new_error_messages.append(error_msg)

    # Combine new errors with existing ones
    current_error_messages = list(state.error_messages or [])
    current_error_messages.extend(new_error_messages)

    return {"persisted_record_id": persisted_id, "error_messages": current_error_messages}
