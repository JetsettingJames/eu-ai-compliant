import asyncio
import tempfile
import shutil
import os
from typing import Tuple, Optional, Dict, Any, List
from datetime import datetime, timezone

from app.models import RepoInputModel, ScanResultModel, ChecklistItem, RepoInfo, CodeSignal, GrepSignalItem, FuzzyMatchResult, RepositoryFile, CodeAnalysisResult, ComplianceAnalysisDetails, TierAnalysis, ComplianceMatch, RiskTier
from app.logger import get_logger
from app.config import settings 
from app.services.llm_service import LLMService
from app.utils.repo_utils import (
    download_repo_zip, 
    unzip_archive,
    find_documentation_files,
    extract_text_and_headings_from_markdown,
    parse_openapi_file,
    find_code_files,
    run_grep_search,
    fetch_github_repo_branch_info
)
from app.utils.compliance import (
    load_and_get_checklist_for_tier,
    determine_risk_tier
)
from app.utils.yaml_config import (
    get_obligations,
    get_risk_tiers,
    get_compliance_config
)
from .vector_processing import (
    upsert_repository_documents,
    upsert_obligation_documents,
    find_matching_obligations_for_repo_doc,
    text_splitter
)
from app.websocket_manager import ConnectionManager
from starlette.concurrency import run_in_threadpool # Added import

logger = get_logger(__name__)

# Placeholder for grep patterns - these would typically be more extensive and configurable
GREP_PATTERNS = [
    "api_key", "secret_key", "password", "token", # Security related
    "biometric", "face_recognition", "voice_recognition", # AI ethics related
    "profiling", "automated_decision_making",
    "TODO:", "FIXME:", "HACK:" # Code quality/maintenance
]

async def _send_ws_progress(ws_manager: Optional[ConnectionManager], scan_id: Optional[str], status: str, detail: Optional[str] = None, data: Optional[Dict[str, Any]] = None):
    if ws_manager and scan_id:
        message_payload = {"status": status}
        if detail:
            message_payload["detail"] = detail
        if data:
            message_payload["data"] = data 
        await ws_manager.send_progress(scan_id, message_payload)
        logger.debug(f"Sent WS progress for {scan_id}: {status} - {detail or ''}")

def analyze_python_code_ast(file_path: str, file_content: str) -> Optional[CodeAnalysisResult]:
    """Placeholder for Python code AST analysis."""
    logger.debug(f"Placeholder AST analysis for Python file: {file_path}")
    # In a real implementation, this would parse the code and return findings.
    # For testing purposes, we return a default CodeAnalysisResult.
    return CodeAnalysisResult(file_path=file_path, imported_modules=[])

def load_full_obligations_data() -> Dict[str, Any]:
    """
    Load the full obligations data from the YAML configuration file.
    
    This function retrieves all compliance obligations organized by risk tier
    from the obligations.yaml file using the yaml_config utilities.
    
    Returns:
        Dictionary containing all obligations data organized by risk tier
    """
    logger.info("Loading obligations data from YAML configuration...")
    try:
        # Get the obligations data using the yaml_config utility
        obligations_data = get_obligations() # from app.utils.yaml_config
        
        if not obligations_data:
            logger.warning("No obligations data found in the YAML configuration.")
            return {}
            
        logger.info(f"Successfully loaded obligations data with {len(obligations_data)} risk tiers.")
        return obligations_data
    except Exception as e:
        logger.error(f"Error loading obligations data: {str(e)}")
        return {}

async def determine_risk_tier(
    doc_summary_bullets: Optional[List[str]],
    code_signals: Optional[CodeSignal],
    grep_signals: Optional[List[GrepSignalItem]],
    obligations_data: Dict[str, Any]
) -> Tuple[str, Dict[str, Any]]:
    """
    Determines the risk tier based on documentation, code signals, and grep signals.
    Returns both the risk tier and detailed analysis information.
    
    Args:
        doc_summary_bullets: List of documentation summary bullet points
        code_signals: Code signals from AST analysis
        grep_signals: Grep signals from keyword search
        obligations_data: Compliance obligations data from YAML
        
    Returns:
        Tuple of (risk_tier, analysis_details)
    """
    logger.info("Performing deep compliance analysis based on documentation, code signals, and grep signals...")
    
    # Initialize analysis details dictionary to capture all findings
    analysis_details = {
        "prohibited": {"matches": [], "score": 0},
        "high": {"matches": [], "score": 0},
        "limited": {"matches": [], "score": 0},
        "minimal": {"matches": [], "score": 0},
        "detected_keywords": [],
        "code_signals": [],
        "documentation_signals": [],
    }
    
    # Enhanced helper to check keywords in various sources and record findings
    def check_keywords(keywords_to_check: List[str], text_sources: List[str], grep_src: Optional[List[GrepSignalItem]], 
                     obligation_id: str = None, obligation_title: str = None) -> List[Dict[str, Any]]:
        matches = []
        if not keywords_to_check: return matches
        
        # Check in text_sources (doc summary)
        for text_idx, text in enumerate(text_sources):
            if not text: continue
            for keyword in keywords_to_check:
                if keyword.lower() in text.lower():
                    match_info = {
                        "keyword": keyword,
                        "source_type": "documentation",
                        "source_content": text,
                        "source_index": text_idx,
                        "obligation_id": obligation_id,
                        "obligation_title": obligation_title,
                        "confidence": 0.9  # High confidence for direct keyword matches
                    }
                    matches.append(match_info)
                    analysis_details["detected_keywords"].append(keyword)
                    analysis_details["documentation_signals"].append(match_info)
                    logger.info(f"Keyword '{keyword}' found in documentation: {text[:100]}...")
        
        # Check in grep_signals
        if grep_src:
            for signal in grep_src:
                for keyword in keywords_to_check:
                    if keyword.lower() in signal.line_content.lower():
                        match_info = {
                            "keyword": keyword,
                            "source_type": "code",
                            "file_path": signal.file_path,
                            "line_number": signal.line_number,
                            "line_content": signal.line_content,
                            "obligation_id": obligation_id,
                            "obligation_title": obligation_title,
                            "confidence": 0.85  # Slightly lower confidence for code matches
                        }
                        matches.append(match_info)
                        analysis_details["detected_keywords"].append(keyword)
                        analysis_details["code_signals"].append(match_info)
                        logger.info(f"Keyword '{keyword}' found in code: {signal.file_path}:{signal.line_number} - {signal.line_content[:100]}...")
        
        return matches
    
    # Analyze all tiers comprehensively to gather complete information
    # We'll determine the final tier after collecting all evidence
    
    # 1. Check for Prohibited AI practices
    prohibited_tier_data = obligations_data.get("prohibited", {})
    prohibited_overall_keywords = prohibited_tier_data.get("overall_tier_keywords", [])
    
    # Check overall tier keywords
    tier_matches = check_keywords(
        prohibited_overall_keywords, 
        doc_summary_bullets or [], 
        grep_signals,
        obligation_id="PROHIBITED_OVERALL",
        obligation_title="Prohibited AI Practices Overall"
    )
    if tier_matches:
        analysis_details["prohibited"]["matches"].extend(tier_matches)
        analysis_details["prohibited"]["score"] += len(tier_matches) * 2  # Higher weight for overall matches
    
    # Check individual obligations
    for obligation in prohibited_tier_data.get("obligations", []):
        obligation_matches = check_keywords(
            obligation.get("keywords", []), 
            doc_summary_bullets or [], 
            grep_signals,
            obligation_id=obligation.get("id"),
            obligation_title=obligation.get("title")
        )
        if obligation_matches:
            analysis_details["prohibited"]["matches"].extend(obligation_matches)
            analysis_details["prohibited"]["score"] += len(obligation_matches) * 1.5
    
    # Add specific code_signals checks for prohibited
    if code_signals:
        if code_signals.biometric and code_signals.live_stream and grep_signals:
            # Check for public spaces in grep signals
            for signal in grep_signals:
                if any(term in signal.line_content.lower() for term in ["public", "space", "surveillance"]):
                    match_info = {
                        "source_type": "code_analysis",
                        "signal_type": "real_time_biometric_in_public_spaces",
                        "file_path": signal.file_path,
                        "line_number": signal.line_number,
                        "line_content": signal.line_content,
                        "obligation_id": "PROHIBIT_BIOMETRIC",
                        "obligation_title": "Real-time Biometric Identification in Public Spaces",
                        "confidence": 0.95
                    }
                    analysis_details["prohibited"]["matches"].append(match_info)
                    analysis_details["prohibited"]["score"] += 3  # Very high score for this prohibited use
                    analysis_details["code_signals"].append(match_info)
                    logger.warning(f"PROHIBITED: Real-time biometric identification in public spaces detected in {signal.file_path}")
    
    # 2. Check for High-Risk AI systems
    high_tier_data = obligations_data.get("high", {})
    high_overall_keywords = high_tier_data.get("overall_tier_keywords", [])
    
    # Check overall tier keywords
    tier_matches = check_keywords(
        high_overall_keywords, 
        doc_summary_bullets or [], 
        grep_signals,
        obligation_id="HIGH_OVERALL",
        obligation_title="High-Risk AI Systems Overall"
    )
    if tier_matches:
        analysis_details["high"]["matches"].extend(tier_matches)
        analysis_details["high"]["score"] += len(tier_matches) * 1.5
    
    # Check individual obligations
    for obligation in high_tier_data.get("obligations", []):
        obligation_matches = check_keywords(
            obligation.get("keywords", []), 
            doc_summary_bullets or [], 
            grep_signals,
            obligation_id=obligation.get("id"),
            obligation_title=obligation.get("title")
        )
        if obligation_matches:
            analysis_details["high"]["matches"].extend(obligation_matches)
            analysis_details["high"]["score"] += len(obligation_matches) * 1.2
    
    # Add specific code_signals checks for high risk
    if code_signals:
        if code_signals.biometric:
            match_info = {
                "source_type": "code_analysis",
                "signal_type": "biometric_identification",
                "obligation_id": "HIGH_BIOMETRIC",
                "obligation_title": "Biometric Identification System",
                "confidence": 0.9
            }
            analysis_details["high"]["matches"].append(match_info)
            analysis_details["high"]["score"] += 2
            analysis_details["code_signals"].append(match_info)
            logger.info("Biometric identification capabilities detected via code analysis, indicating HIGH risk.")
        
        # if code_signals.critical_infrastructure: # Commenting out as 'critical_infrastructure' is not on CodeSignal model
        #     analysis_details["high"]["matches"].append({
        #         "keyword": "critical_infrastructure_signal", 
        #         "source_type": "code_signal", 
        #         "confidence": 0.9,
        #         "reason": "Detected code signal related to critical infrastructure."
        #     })
        #     analysis_details["high"]["score"] += 5 
        #     logger.info("Code signal: Potential critical infrastructure usage detected.")

        # if code_signals.education_vocational_training: # Commenting out as 'education_vocational_training' is not on CodeSignal model
        #     analysis_details["high"]["matches"].append({
        #         "keyword": "education_signal", 
        #         "source_type": "code_signal", 
        #         "confidence": 0.9,
        #         "reason": "Detected code signal related to education/vocational training."
        #     })
        #     analysis_details["high"]["score"] += 5
        #     logger.info("Code signal: Potential education/vocational training usage detected.")
        pass # Placeholder for valid CodeSignal checks for high risk

    # 3. Check for Limited Risk AI systems
    limited_tier_data = obligations_data.get("limited", {})
    limited_overall_keywords = limited_tier_data.get("overall_tier_keywords", [])
    
    # Check overall tier keywords
    tier_matches = check_keywords(
        limited_overall_keywords, 
        doc_summary_bullets or [], 
        grep_signals,
        obligation_id="LIMITED_OVERALL",
        obligation_title="Limited Risk AI Systems Overall"
    )
    if tier_matches:
        analysis_details["limited"]["matches"].extend(tier_matches)
        analysis_details["limited"]["score"] += len(tier_matches) * 1.2
    
    # Check individual obligations
    for obligation in limited_tier_data.get("obligations", []):
        obligation_matches = check_keywords(
            obligation.get("keywords", []), 
            doc_summary_bullets or [], 
            grep_signals,
            obligation_id=obligation.get("id"),
            obligation_title=obligation.get("title")
        )
        if obligation_matches:
            analysis_details["limited"]["matches"].extend(obligation_matches)
            analysis_details["limited"]["score"] += len(obligation_matches)
    
    # Add specific code_signals checks for limited risk
    if code_signals:
        if code_signals.uses_gpai:
            match_info = {
                "source_type": "code_analysis",
                "signal_type": "general_purpose_ai",
                "obligation_id": "LIMITED_GPAI",
                "obligation_title": "General Purpose AI / LLM Usage",
                "confidence": 0.85
            }
            analysis_details["limited"]["matches"].append(match_info)
            analysis_details["limited"]["score"] += 1.5
            analysis_details["code_signals"].append(match_info)
            logger.info("General Purpose AI / LLM usage detected via code analysis, indicating LIMITED risk.")
        
        # if code_signals.emotion_recognition: # Commenting out as 'emotion_recognition' is not on CodeSignal model
        #     analysis_details["limited"]["matches"].append({
        #         "keyword": "emotion_recognition_signal", 
        #         "source_type": "code_signal", 
        #         "confidence": 0.8,
        #         "reason": "Detected code signal related to emotion recognition."
        #     })
        #     analysis_details["limited"]["score"] += 3
        #     logger.info("Code signal: Potential emotion recognition usage detected.")

        # if code_signals.deep_fake_generation: # Commenting out as 'deep_fake_generation' is not on CodeSignal model
        #     analysis_details["limited"]["matches"].append({
        #         "keyword": "deep_fake_signal", 
        #         "source_type": "code_signal", 
        #         "confidence": 0.8,
        #         "reason": "Detected code signal related to deep fake generation."
        #     })
        #     analysis_details["limited"]["score"] += 3
        #     logger.info("Code signal: Potential deep fake generation usage detected.")
        pass # Placeholder for valid CodeSignal checks for limited risk

    # 4. Check for Minimal Risk AI systems (default)
    # If no specific signals are found, it's minimal risk
    if not any([analysis_details["prohibited"]["matches"], 
                analysis_details["high"]["matches"], 
                analysis_details["limited"]["matches"]]):
        analysis_details["minimal"]["score"] = 1
        analysis_details["minimal"]["matches"].append({
            "source_type": "default",
            "signal_type": "minimal_risk_default",
            "obligation_id": "MINIMAL_DEFAULT",
            "obligation_title": "Minimal Risk AI System",
            "confidence": 0.7,
            "reason": "No specific prohibited, high, or limited risk signals identified"
        })
    
    # Determine the final risk tier based on the scores
    # Order of precedence: prohibited > high > limited > minimal
    if analysis_details["prohibited"]["score"] > 0:
        logger.warning(f"PROHIBITED risk tier determined with score {analysis_details['prohibited']['score']} based on {len(analysis_details['prohibited']['matches'])} matches")
        return "prohibited", analysis_details
    elif analysis_details["high"]["score"] > 0:
        logger.info(f"HIGH risk tier determined with score {analysis_details['high']['score']} based on {len(analysis_details['high']['matches'])} matches")
        return "high", analysis_details
    elif analysis_details["limited"]["score"] > 0:
        logger.info(f"LIMITED risk tier determined with score {analysis_details['limited']['score']} based on {len(analysis_details['limited']['matches'])} matches")
        return "limited", analysis_details
    else:
        logger.info("MINIMAL risk tier determined (default classification)")
        return "minimal", analysis_details


async def scan_repo(input_data: RepoInputModel, scan_id: Optional[str] = None, ws_manager: Optional[ConnectionManager] = None) -> ScanResultModel:
    """Orchestrates the 7-step repository scanning process."""
    await _send_ws_progress(ws_manager, scan_id, "starting", "Scan process initiated.")
    
    logger.info(f"Starting scan for input: {input_data.model_dump_json(exclude_none=True)}")
    temp_dir = None
    llm_service = LLMService()
    all_fuzzy_matches: List[FuzzyMatchResult] = [] # Initialize here for broader scope
    repo_files_for_embedding: List[RepositoryFile] = []
    file_contents_cache: Dict[str, Optional[str]] = {} 

    try:
        # --- Initial Setup: Load and Upsert Obligations (once or if needed) ---
        logger.info("Loading full obligations data...")
        full_obligations_data = load_full_obligations_data() 

        if full_obligations_data:
            logger.info("Upserting obligation documents to ChromaDB...")
            obligation_doc_ids = await upsert_obligation_documents(full_obligations_data)
            logger.info(f"Upserted {len(obligation_doc_ids)} obligation documents.")
        else:
            logger.error("Failed to load obligations data. Vector-assisted features will be impacted.")
            # Decide if scan should continue or raise an error

        # Step 0: Resolve input and get repository archive info
        await _send_ws_progress(ws_manager, scan_id, "progress", "Step 0: Resolving repository input and getting archive info...")
        repo_info = await resolve_repo_input(input_data)
        target_branch, actual_commit_sha = await fetch_github_repo_branch_info(
            owner=repo_info.owner,
            repo_name=repo_info.repo,
            branch_name=repo_info.branch, # This can be None, handled by fetch_github_repo_branch_info
            token=settings.GITHUB_TOKEN
        )
        logger.info(f"Target branch: {target_branch}, Commit SHA: {actual_commit_sha}")
        archive_url = f"https://github.com/{repo_info.owner}/{repo_info.repo}/archive/{actual_commit_sha}.zip"
        
        temp_dir = tempfile.mkdtemp(prefix="repo_scan_")
        
        # Step 1: Fetch & Unzip
        logger.info("Step 1: Fetching and unzipping repository...")
        # Pass only archive_url and token to the updated async download_repo_zip
        zip_path = await download_repo_zip(archive_url, token=settings.GITHUB_TOKEN)
        if not zip_path:
            logger.error(f"Failed to download repository from {archive_url}")
            await _send_ws_progress(ws_manager, scan_id, "error", f"Failed to download repository from {archive_url}")
            # Consider how to handle this error - perhaps raise an exception or return an error model
            raise ValueError(f"Failed to download repository from {archive_url}")
            
        logger.info(f"Repository ZIP downloaded to: {zip_path}")
        # Use run_in_threadpool for the synchronous unzip_archive function
        unzipped_path = await run_in_threadpool(
            unzip_archive, 
            zip_path=zip_path, 
            extract_to_dir=temp_dir
        )
        if not unzipped_path:
            logger.error(f"Failed to unzip repository archive {zip_path}")
            await _send_ws_progress(ws_manager, scan_id, "error", f"Failed to unzip repository archive {zip_path}")
            # Clean up the downloaded zip file if unzipping fails
            if os.path.exists(zip_path):
                try:
                    os.remove(zip_path)
                    logger.info(f"Cleaned up failed download: {zip_path}")
                except OSError as e_remove:
                    logger.error(f"Error cleaning up failed download {zip_path}: {e_remove}")
            raise ValueError(f"Failed to unzip repository archive {zip_path}")

        logger.info(f"Repository unzipped to: {unzipped_path}")

        # --- Collect all unique file paths that need reading ---
        all_paths_to_read_abs = set()

        # Update paths to be relative to the actual unzipped_path root
        # find_documentation_files returns a tuple: (markdown_files_rel, openapi_files_rel)
        markdown_files_rel, openapi_files_rel = find_documentation_files(unzipped_path)
        
        doc_files_abs = [
            os.path.join(unzipped_path, rel_path) 
            for rel_path in markdown_files_rel + openapi_files_rel # Combine both lists
        ]
        all_paths_to_read_abs.update(doc_files_abs)

        # openapi_specs_rel is now directly available
        openapi_specs_abs = [os.path.join(unzipped_path, rel_path) for rel_path in openapi_files_rel]

        code_files_by_lang_rel = find_code_files(unzipped_path)
        python_files_for_ast_abs = [os.path.join(unzipped_path, rel_path) for rel_path in code_files_by_lang_rel.get('python', [])]
        all_paths_to_read_abs.update(python_files_for_ast_abs)

        all_code_files_abs = [
            os.path.join(unzipped_path, rel_path) 
            for lang_paths in code_files_by_lang_rel.values() for rel_path in lang_paths
        ]
        all_paths_to_read_abs.update(all_code_files_abs)

        # --- Read all unique files ONCE and cache their content ---
        logger.info(f"Caching content for {len(all_paths_to_read_abs)} unique files...")
        for file_path_abs in all_paths_to_read_abs:
            try:
                # Use 'errors=ignore' as a general policy for caching, 
                # specific parsing can be more strict if needed.
                with open(file_path_abs, 'r', encoding='utf-8', errors='ignore') as f:
                    # logger.debug(f"CACHE_READ: Successfully opened {file_path_abs} to cache content.") # Optional: too verbose
                    file_contents_cache[file_path_abs] = f.read()
            except FileNotFoundError:
                logger.warning(f"File not found during caching: {file_path_abs}")
                file_contents_cache[file_path_abs] = None
            except Exception as e:
                logger.error(f"Error reading file {file_path_abs} during caching: {e}")
                file_contents_cache[file_path_abs] = None
        logger.info("File content caching complete.")

        # Step 2: Extract Documentation (Markdown, OpenAPI)
        logger.info("Step 2: Extracting documentation (Markdown, OpenAPI)...")
        all_markdown_text_list: List[str] = []
        all_headings: List[str] = []
        openapi_specs_summary: List[Dict[str, Any]] = []

        markdown_file_paths_abs = [os.path.join(unzipped_path, rel_path) for rel_path in markdown_files_rel]
        for md_file_path in markdown_file_paths_abs:
            logger.info(f"Processing Markdown file (from cache): {md_file_path}")
            # extract_text_and_headings_from_markdown expects a path, and it's mocked in tests
            # The real function opens the file, but in tests, the mock is called.
            # If we had a version that takes content, we'd use file_contents_cache[md_file_path]
            try:
                text, headings = extract_text_and_headings_from_markdown(md_file_path)
                if text: all_markdown_text_list.append(text)
                if headings: all_headings.extend(headings)
            except Exception as e:
                logger.error(f"Error processing Markdown file {md_file_path} (using path): {e}")
        
        combined_markdown_text = "\n\n---\n\n".join(all_markdown_text_list)

        for spec_file_path in openapi_specs_abs:
            logger.info(f"Processing potential OpenAPI/Swagger file (from cache): {spec_file_path}")
            # parse_openapi_file expects a path, and it's mocked in tests.
            try:
                spec_info = parse_openapi_file(spec_file_path)
                if spec_info: openapi_specs_summary.append(spec_info)
            except Exception as e:
                logger.error(f"Error processing OpenAPI file {spec_file_path} (using path): {e}")

        # Step 3: Summarise with LLM
        logger.info("Step 3: Summarising documentation with LLM...")
        doc_summary_bullets: Optional[List[str]] = None
        if llm_service.aclient: # Check if the aclient is initialized (i.e., API key was provided)
            logger.info("LLM service is configured. Proceeding with documentation summary.")
            try:
                # Use run_in_threadpool for the potentially blocking LLM call
                doc_summary_bullets = await llm_service.get_llm_summary( # Renamed from summarize_documentation
                    markdown_text=combined_markdown_text,
                    headings=all_headings,
                )
                logger.info(f"LLM summarization complete. Bullets: {len(doc_summary_bullets)}")
            except Exception as e:
                logger.error(f"Error during LLM summarization: {e}")
        else:
            if not combined_markdown_text and not openapi_specs_summary:
                doc_summary_bullets = ["Warning: No significant documentation found and LLM summarization skipped (API key missing)."]
            else:
                doc_summary_bullets = [
                    "Placeholder: LLM summarization skipped (API key missing).",
                    f"Markdown text length: {len(combined_markdown_text)}, Headings found: {len(all_headings)}, OpenAPI specs: {len(openapi_specs_summary)}"
                ]
            logger.info("Using placeholder documentation summary.")

        # Step 3a: AST Analysis (Python only for now)
        logger.info("Step 3a: Performing AST analysis for Python files...")
        final_code_signals = CodeSignal(uses_gpai=False) # Default
        # python_files_for_ast_abs already defined

        for file_path_abs in python_files_for_ast_abs:
            logger.debug(f"Analyzing Python file (AST from cache): {file_path_abs}")
            file_content = file_contents_cache.get(file_path_abs)
            if file_content is None:
                logger.warning(f"Skipping AST analysis for {file_path_abs}, content not available.")
                continue
            try:
                # analyze_python_code_ast expects path and content.
                analysis_result: Optional[CodeAnalysisResult] = analyze_python_code_ast(file_path_abs, file_content)
                if analysis_result and analysis_result.uses_gpai:
                    final_code_signals.uses_gpai = True
                    logger.info(f"GPAI usage detected by AST analysis in: {file_path_abs}")
            except Exception as e:
                logger.error(f"Error during AST analysis of {file_path_abs}: {e}")

        # Step 3b: Prepare content for vector embedding (docs, code, api specs)
        logger.info("Step 3b: Preparing content for vector embedding...")
        # repo_files_for_embedding already initialized

        # Process Markdown files for embedding
        markdown_file_paths_rel = markdown_files_rel
        for md_file_rel_path in markdown_file_paths_rel: # Use the specific list of markdown files
            md_file_abs_path = os.path.join(unzipped_path, md_file_rel_path)
            content = file_contents_cache.get(md_file_abs_path)
            if content is not None:
                repo_files_for_embedding.append(RepositoryFile(
                    path=md_file_rel_path, # Store relative path
                    content=content,
                    file_type='markdown'
                ))
            else:
                logger.warning(f"Could not prepare (embedding) doc file {md_file_abs_path}: content not in cache.")

        # Process all code files for embedding (includes Python, JS, TS etc.)
        all_code_files_rel_paths = [
            rel_path for lang_paths in code_files_by_lang_rel.values() for rel_path in lang_paths
        ]
        for code_file_rel_path in all_code_files_rel_paths:
            code_file_abs_path = os.path.join(unzipped_path, code_file_rel_path)
            content = file_contents_cache.get(code_file_abs_path)
            if content is not None:
                file_extension = os.path.splitext(code_file_abs_path)[1].lower()
                repo_files_for_embedding.append(RepositoryFile(
                    path=code_file_rel_path, # Store relative path
                    content=content,
                    file_type=f"code_{file_extension.lstrip('.')}" 
                ))
            else:
                logger.warning(f"Could not prepare (embedding) code file {code_file_abs_path}: content not in cache.")

        # Process OpenAPI spec files for embedding
        openapi_specs_rel = openapi_files_rel
        for api_spec_rel_path in openapi_specs_rel:
            api_spec_abs_path = os.path.join(unzipped_path, api_spec_rel_path)
            content = file_contents_cache.get(api_spec_abs_path)
            if content is not None:
                repo_files_for_embedding.append(RepositoryFile(
                    path=api_spec_rel_path, # Store relative path
                    content=content,
                    file_type='openapi'
                ))
            else:
                logger.warning(f"Could not prepare (embedding) API spec file {api_spec_abs_path}: content not in cache.")

        # Step 3c: Grep Search (if configured)
        logger.info("Step 2 (Agent Spec): Grep Risk Signals...")
        # run_grep_search expects the root directory of the unzipped repo and patterns
        grep_search_results_raw: List[Dict[str, Any]] = await run_in_threadpool(
            run_grep_search, 
            repo_dir=unzipped_path,
            patterns=GREP_PATTERNS # Pass the defined patterns
        )
        # Convert raw dicts to GrepSignalItem models
        # Pydantic will ignore the extra 'pattern' key from run_grep_search's dicts
        grep_signals_found: List[GrepSignalItem] = [
            GrepSignalItem(**item) for item in grep_search_results_raw
        ]
        logger.info(f"Found {len(grep_signals_found)} grep signals.")

        # --- Vector-Assisted Fuzzy Classification Steps (Refactored for ChromaDB) ---
        if llm_service.aclient and full_obligations_data:
            if repo_files_for_embedding:
                logger.info("Upserting repository documents to ChromaDB...")
                repo_doc_ids = await upsert_repository_documents(repo_files_for_embedding)
                logger.info(f"Upserted {len(repo_doc_ids)} repository documents/chunks to ChromaDB.")

                logger.info("Finding fuzzy matches: comparing repository content against obligations in ChromaDB...")
                cumulative_fuzzy_matches: List[FuzzyMatchResult] = []
                for repo_file_item in repo_files_for_embedding:
                    if not repo_file_item.content:
                        continue
                    
                    file_chunks = text_splitter.split_text(repo_file_item.content)
                    
                    for i, chunk_text in enumerate(file_chunks):
                        chunk_metadata = {
                            "source_type": "repository_file", # Consistent with ChromaDB metadata
                            "source_identifier": repo_file_item.path, 
                            "file_type": repo_file_item.file_type,
                            "language": getattr(repo_file_item, 'language', None) if repo_file_item.file_type == "code" else None,
                            "chunk_index": i
                        }
                        matches_for_chunk = await find_matching_obligations_for_repo_doc(
                            repo_doc_content=chunk_text,
                            repo_doc_metadata=chunk_metadata # Pass metadata of the repo chunk
                        )
                        cumulative_fuzzy_matches.extend(matches_for_chunk)
                
                all_fuzzy_matches = cumulative_fuzzy_matches # Assign to the variable used later
                logger.info(f"Found a total of {len(all_fuzzy_matches)} fuzzy matches after processing all repo content.")
            else:
                logger.info("No repository content prepared for embedding/matching. Skipping vector-based fuzzy matching.")
        else:
            logger.warning("Skipping vector-assisted fuzzy classification: LLMService not configured, obligations not loaded, or no repo content.")
        # --- END: Vector-Assisted Fuzzy Classification Steps ---

        # Step 5: Classify risk tier with detailed analysis
        logger.info("Step 5: Performing deep compliance analysis...")
        determined_tier, analysis_details = await determine_risk_tier(
            doc_summary_bullets, 
            final_code_signals, 
            grep_signals_found,
            full_obligations_data
        )
        logger.info(f"Determined risk tier: {determined_tier} with {len(analysis_details.get(determined_tier, {}).get('matches', []))} matches")
        
        # Log detailed analysis information
        logger.info(f"Analysis details: Found {len(analysis_details.get('detected_keywords', []))} keywords, {len(analysis_details.get('code_signals', []))} code signals, and {len(analysis_details.get('documentation_signals', []))} documentation signals")
        
        # Step 6: Lookup checklist
        logger.info("Step 6: Looking up checklist based on tier...")
        checklist_items = load_and_get_checklist_for_tier(determined_tier, full_obligations_data)

        # Step 7: Persist & Respond (Assemble ScanResultModel)
        logger.info("Step 7: Assembling final scan result with detailed analysis...")
        
        # Convert the analysis_details dict to a ComplianceAnalysisDetails model
        from app.models import ComplianceAnalysisDetails, TierAnalysis, ComplianceMatch
        
        # Create the ComplianceAnalysisDetails model from the analysis_details dict
        compliance_analysis = ComplianceAnalysisDetails(
            prohibited=TierAnalysis(
                matches=[ComplianceMatch(**match) for match in analysis_details.get("prohibited", {}).get("matches", [])],
                score=analysis_details.get("prohibited", {}).get("score", 0)
            ),
            high=TierAnalysis(
                matches=[ComplianceMatch(**match) for match in analysis_details.get("high", {}).get("matches", [])],
                score=analysis_details.get("high", {}).get("score", 0)
            ),
            limited=TierAnalysis(
                matches=[ComplianceMatch(**match) for match in analysis_details.get("limited", {}).get("matches", [])],
                score=analysis_details.get("limited", {}).get("score", 0)
            ),
            minimal=TierAnalysis(
                matches=[ComplianceMatch(**match) for match in analysis_details.get("minimal", {}).get("matches", [])],
                score=analysis_details.get("minimal", {}).get("score", 0)
            ),
            detected_keywords=analysis_details.get("detected_keywords", []),
            code_signals=[ComplianceMatch(**signal) for signal in analysis_details.get("code_signals", [])],
            documentation_signals=[ComplianceMatch(**signal) for signal in analysis_details.get("documentation_signals", [])]
        )
        
        # Create evidence snippets from the analysis details
        evidence_snippets = {}
        
        # Add code snippets from code signals
        for i, signal in enumerate(analysis_details.get("code_signals", [])):
            if signal.get("file_path") and signal.get("line_content"):
                key = f"code_snippet_{i+1}"
                evidence_snippets[key] = {
                    "file": signal.get("file_path"),
                    "line": signal.get("line_number"),
                    "content": signal.get("line_content"),
                    "obligation_id": signal.get("obligation_id"),
                    "obligation_title": signal.get("obligation_title"),
                    "confidence": signal.get("confidence")
                }
        
        # Add documentation snippets from documentation signals
        for i, signal in enumerate(analysis_details.get("documentation_signals", [])):
            if signal.get("source_content"):
                key = f"doc_snippet_{i+1}"
                evidence_snippets[key] = {
                    "content": signal.get("source_content"),
                    "obligation_id": signal.get("obligation_id"),
                    "obligation_title": signal.get("obligation_title"),
                    "confidence": signal.get("confidence")
                }
        
        scan_result = ScanResultModel(
            tier=determined_tier,
            checklist=checklist_items,
            doc_summary=doc_summary_bullets,
            code_signals=final_code_signals,
            grep_signals=grep_signals_found,
            fuzzy_matches=all_fuzzy_matches, 
            repo_url=f"https://github.com/{repo_info.owner}/{repo_info.repo}",
            commit_sha=actual_commit_sha, 
            timestamp=datetime.now(timezone.utc),
            evidence_snippets=evidence_snippets,
            analysis_details=compliance_analysis
        )
        
        logger.info(f"Scan complete. Tier: {determined_tier}. Fuzzy matches: {len(all_fuzzy_matches)}. Final result: {scan_result.model_dump_json(indent=2, exclude_none=True)}")
        await _send_ws_progress(ws_manager, scan_id, "completed", "Scan completed successfully.", {"tier": determined_tier, "result_summary": scan_result.model_dump(exclude_none=True, mode='json')})
        return scan_result

    except Exception as inner_e: # Exception handler for the INNER try block (core scanning steps)
        logger.error(f"Error during core repository scanning steps (1-7): {inner_e}", exc_info=True)
        await _send_ws_progress(ws_manager, scan_id, "error", "An error occurred during the scan.", {"error_details": str(inner_e)})
        raise # Re-raise the exception to be caught by the outer try's except block or propagate

    except Exception as e: # Outer try's exception handler
        logger.error(f"Overall error in scan_repo: {e}", exc_info=True)
        await _send_ws_progress(ws_manager, scan_id, "error", "An error occurred during the scan.", {"error_details": str(e)})
        raise
    finally: # Outer try's finally block (ensures temp_dir cleanup)
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info(f"Cleaned up temporary directory: {temp_dir}")


async def resolve_repo_input(input_data: RepoInputModel) -> RepoInfo:
    """Resolves RepoInputModel to definitive owner, repo, and branch."""
    if input_data.repo_details:
        logger.info(f"Using provided repo details: {input_data.repo_details.owner}/{input_data.repo_details.repo}")
        return input_data.repo_details
    elif input_data.repo_url:
        path_parts = input_data.repo_url.path.strip('/').split('/')
        if len(path_parts) < 2:
            raise ValueError("Invalid GitHub URL: could not extract owner and repo.")
        owner = path_parts[0]
        repo = path_parts[1]
        branch = None
        if len(path_parts) > 3 and path_parts[2] == 'tree':
            branch = path_parts[3]
        logger.info(f"Extracted repo details from URL: {owner}/{repo}, branch: {branch}")
        return RepoInfo(owner=owner, repo=repo, branch=branch)
    else:
        raise ValueError("No repository input (URL or details) provided.")


# Example usage (for testing this file directly, optional):
# async def main():
#     test_input = RepoInputModel(repo_details=RepoInfo(owner="testowner", repo="testrepo"))
#     try:
#         result = await scan_repo(test_input)
#         print("Scan Result:")
#         print(result.model_dump_json(indent=2))
#     except Exception as e:
#         print(f"An error occurred: {e}")

# if __name__ == "__main__":
#     asyncio.run(main())
