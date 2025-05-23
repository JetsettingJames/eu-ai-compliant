# This file will contain utility functions for the application.
# For example:
# - GitHub API interactions (downloading repo, getting commit SHA)
# - File system operations (unzipping, walking directories)
# - Text processing (Markdown parsing, OpenAPI parsing)
# - Code analysis helpers (AST node visitors)

import httpx
import os
import zipfile
from typing import Tuple, Optional, Dict, Any, List

from .models import RepoInfo # Assuming models.py is in the same directory or accessible
from .logger import get_logger
from .config import settings

logger = get_logger(__name__)

async def get_repo_archive_info(repo_info: RepoInfo, token: Optional[str]) -> Tuple[str, str]:
    """
    Fetches the target branch name (resolving default if necessary) and its latest commit SHA.

    Args:
        repo_info: RepoInfo object with owner and repo, and optionally branch.
        token: GitHub API token.

    Returns:
        A tuple (target_branch_name, commit_sha).
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
        # 1. Determine the branch to use (default or specified)
        target_branch_name = repo_info.branch
        if not target_branch_name:
            repo_url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}"
            logger.info(f"Fetching default branch for {repo_info.owner}/{repo_info.repo} from {repo_url}")
            try:
                response = await client.get(repo_url)
                response.raise_for_status() # Raise an exception for HTTP errors
                repo_data = response.json()
                target_branch_name = repo_data.get("default_branch")
                if not target_branch_name:
                    raise ValueError(f"Could not determine default branch for {repo_info.owner}/{repo_info.repo}")
                logger.info(f"Default branch for {repo_info.owner}/{repo_info.repo} is {target_branch_name}")
            except httpx.HTTPStatusError as e:
                logger.error(f"GitHub API error fetching repo details: {e.response.status_code} - {e.response.text}")
                raise ValueError(f"Failed to fetch repo details for {repo_info.owner}/{repo_info.repo}: {e.response.status_code}") from e
            except Exception as e:
                logger.error(f"Error determining default branch: {e}")
                raise

        # 2. Get the commit SHA for the target branch
        branch_url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}/branches/{target_branch_name}"
        logger.info(f"Fetching commit SHA for branch '{target_branch_name}' from {branch_url}")
        try:
            response = await client.get(branch_url)
            response.raise_for_status()
            branch_data = response.json()
            commit_sha = branch_data.get("commit", {}).get("sha")
            if not commit_sha:
                raise ValueError(f"Could not determine commit SHA for branch {target_branch_name}")
            logger.info(f"Commit SHA for {repo_info.owner}/{repo_info.repo}@{target_branch_name} is {commit_sha}")
            return target_branch_name, commit_sha
        except httpx.HTTPStatusError as e:
            logger.error(f"GitHub API error fetching branch details: {e.response.status_code} - {e.response.text}")
            raise ValueError(f"Failed to fetch branch details for {target_branch_name}: {e.response.status_code}") from e
        except Exception as e:
            logger.error(f"Error determining commit SHA: {e}")
            raise

async def download_repo_zip(
    repo_info: RepoInfo, 
    commit_sha_or_branch: str, 
    token: Optional[str], 
    download_dir: str
) -> str:
    """
    Downloads the repository as a ZIP archive for a specific commit SHA or branch.

    Args:
        repo_info: RepoInfo object with owner and repo.
        commit_sha_or_branch: The commit SHA or branch name to download.
        token: GitHub API token.
        download_dir: Directory to save the downloaded ZIP file.

    Returns:
        Path to the downloaded ZIP file.
    """
    zip_url = f"https://api.github.com/repos/{repo_info.owner}/{repo_info.repo}/zipball/{commit_sha_or_branch}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    
    zip_filename = f"{repo_info.owner}_{repo_info.repo}_{commit_sha_or_branch.replace('/', '_')}.zip"
    zip_path = os.path.join(download_dir, zip_filename)

    logger.info(f"Downloading repository from {zip_url} to {zip_path}")

    # Use a context manager for the client to ensure it's closed properly
    async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=60.0) as client:
        try:
            # Stream the download to handle potentially large files
            async with client.stream("GET", zip_url) as response:
                response.raise_for_status() # Check for HTTP errors
                
                with open(zip_path, 'wb') as f:
                    async for chunk in response.aiter_bytes():
                        f.write(chunk)
            logger.info(f"Successfully downloaded repository to {zip_path}")
            return zip_path
        except httpx.HTTPStatusError as e:
            logger.error(f"GitHub API error during download: {e.response.status_code} - {e.response.text}")
            if os.path.exists(zip_path): # Clean up partial download
                os.remove(zip_path)
            raise ValueError(f"Failed to download repository: {e.response.status_code}") from e
        except Exception as e:
            logger.error(f"Error downloading repository: {e}")
            if os.path.exists(zip_path): # Clean up partial download
                os.remove(zip_path)
            raise

async def unzip_archive(zip_path: str, extract_to_dir: str, max_size_mb: int = 50) -> str:
    """
    Unzips an archive to a specified directory, checking for total size.
    Identifies and returns the path to the primary content directory within the zip.

    Args:
        zip_path: Path to the ZIP file.
        extract_to_dir: Directory where the ZIP contents should be extracted.
        max_size_mb: Maximum allowed uncompressed size in megabytes.

    Returns:
        Path to the extracted repository content (e.g., 'extract_to_dir/owner-repo-commitsha/').
    """
    max_size_bytes = max_size_mb * 1024 * 1024
    extracted_size = 0
    # Create a subdirectory for extraction to avoid clutter and name collisions
    # GitHub zips usually contain a single root folder like 'owner-repo-commitsha'
    # We'll extract into a generic 'unzipped_content' and then find the actual repo folder.
    temp_extract_path = os.path.join(extract_to_dir, "_temp_unzip_target") 
    os.makedirs(temp_extract_path, exist_ok=True)

    repo_root_folder_name = None

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Get the list of all files and directories in the zip
            file_infos = zip_ref.infolist()
            if not file_infos:
                raise ValueError("ZIP file is empty.")

            # Determine the root folder name (common prefix for all files/dirs at the root)
            # e.g., 'myrepo-main/'
            # This assumes a standard GitHub zip structure.
            first_item_path_parts = file_infos[0].filename.split('/')
            if len(first_item_path_parts) > 0 and file_infos[0].filename.endswith('/'):
                repo_root_folder_name_candidate = first_item_path_parts[0]
                # Verify this is a common root for most/all items
                if all(f.filename.startswith(repo_root_folder_name_candidate) for f in file_infos):
                    repo_root_folder_name = repo_root_folder_name_candidate
                    logger.info(f"Identified repo root folder in ZIP: {repo_root_folder_name}")

            for member in file_infos:
                extracted_size += member.file_size
                if extracted_size > max_size_bytes:
                    raise ValueError(
                        f"Uncompressed size ({extracted_size / (1024*1024):.2f}MB) "
                        f"exceeds maximum allowed size ({max_size_mb}MB)."
                    )
                # Security: Check for path traversal vulnerabilities (though ZipFile usually handles this well)
                if member.filename.startswith('/') or '..' in member.filename:
                    logger.warning(f"Skipping potentially unsafe path in ZIP: {member.filename}")
                    continue
                
                zip_ref.extract(member, path=temp_extract_path)
        
        logger.info(f"Successfully unzipped {zip_path} to {temp_extract_path}. Total size: {extracted_size / (1024*1024):.2f}MB")
        
        # Determine the actual content path (inside the typically single root folder)
        if repo_root_folder_name:
            content_path = os.path.join(temp_extract_path, repo_root_folder_name)
            if os.path.isdir(content_path):
                logger.info(f"Actual repository content assumed to be in: {content_path}")
                return content_path
            else:
                logger.warning(f"Expected root folder '{repo_root_folder_name}' not found as a directory after extraction.")
        
        # Fallback if specific root folder wasn't clearly identified or if zip is flat
        # Check if temp_extract_path has exactly one subdirectory, assume that's it.
        extracted_items = os.listdir(temp_extract_path)
        if len(extracted_items) == 1 and os.path.isdir(os.path.join(temp_extract_path, extracted_items[0])):
            content_path = os.path.join(temp_extract_path, extracted_items[0])
            logger.info(f"Found single subdirectory, assuming it's the content path: {content_path}")
            return content_path
        
        # If no clear single root, return the temp_extract_path itself (less ideal)
        logger.info(f"No single root folder identified or multiple items at root. Using extraction path: {temp_extract_path}")
        return temp_extract_path

    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file: {zip_path}")
        raise ValueError(f"Invalid or corrupted ZIP file: {os.path.basename(zip_path)}")
    except Exception as e:
        logger.error(f"Error unzipping archive {zip_path}: {e}")
        raise
    finally:
        # The caller (scanner.py) is responsible for cleaning up the parent temp_dir.
        # We don't remove temp_extract_path here as it might contain the returned content_path.
        pass 

import glob
from markdown_it import MarkdownIt
from bs4 import BeautifulSoup

MAX_DOC_WORDS = 2000

def find_documentation_files(repo_path: str) -> Dict[str, list[str]]:
    """
    Finds relevant documentation files (Markdown, OpenAPI) in the repository.

    Args:
        repo_path: The root path of the unzipped repository.

    Returns:
        A dictionary with keys 'markdown' and 'openapi' containing lists of file paths.
    """
    logger.info(f"--- Debug: find_documentation_files --- Entering function.")
    logger.info(f"--- Debug: find_documentation_files --- repo_path: {repo_path}")
    try:
        repo_path_contents = os.listdir(repo_path)
        logger.info(f"--- Debug: find_documentation_files --- Contents of repo_path ({len(repo_path_contents)} items): {repo_path_contents}")
    except Exception as e:
        logger.error(f"--- Debug: find_documentation_files --- Error listing {repo_path}: {e}")

    markdown_files = []
    openapi_files = []

    # 1. Find README.md or README.rst at the root of repo_path
    root_readme_md_path = os.path.join(repo_path, "README.md")
    root_readme_rst_path = os.path.join(repo_path, "README.rst")

    if os.path.isfile(root_readme_md_path):
        markdown_files.append(os.path.normpath(root_readme_md_path))
        logger.info(f"Found root README.md: {root_readme_md_path}")
    elif os.path.isfile(root_readme_rst_path):
        markdown_files.append(os.path.normpath(root_readme_rst_path))
        logger.info(f"Found root README.rst: {root_readme_rst_path}")

    # 2. Find all other .md and .rst files recursively
    for ext_pattern in ["*.md", "*.rst"]:
        for doc_file_path in glob.glob(os.path.join(repo_path, "**", ext_pattern), recursive=True):
            normalized_path = os.path.normpath(doc_file_path)
            if normalized_path not in markdown_files: # Avoid adding root README again
                markdown_files.append(normalized_path)
    
    markdown_files = sorted(list(set(markdown_files)))

    # 3. OpenAPI files (YAML or JSON)
    # Look for common names and locations, then broader search
    common_openapi_names = [
        "openapi.yaml", "openapi.json", 
        "swagger.yaml", "swagger.json",
        "api.yaml", "api.json"
    ]
    for name in common_openapi_names:
        for openapi_path in glob.glob(os.path.join(repo_path, "**", name), recursive=True):
            openapi_files.append(os.path.normpath(openapi_path))

    # Broader search for any .yaml or .json that might be OpenAPI (can be refined later)
    for ext in ["*.yaml", "*.yml", "*.json"]:
        for file_path in glob.glob(os.path.join(repo_path, "**", ext), recursive=True):
            # Avoid adding large non-OpenAPI JSON/YAMLs if possible, or filter later
            # For now, add all and let parsing step try
            norm_path = os.path.normpath(file_path)
            if norm_path not in openapi_files:
                 openapi_files.append(norm_path)

    openapi_files = sorted(list(set(openapi_files)))

    logger.info(f"Found {len(markdown_files)} potential Markdown files: {markdown_files}")
    logger.info(f"Found {len(openapi_files)} potential OpenAPI files: {openapi_files}")

    return {
        "markdown": markdown_files,
        "openapi": openapi_files
    }


def extract_text_and_headings_from_markdown(file_path: str) -> Tuple[str, list[str]]:
    """
    Extracts text (up to MAX_DOC_WORDS) and H1-H3 headings from a Markdown file.

    Args:
        file_path: Path to the Markdown file.

    Returns:
        A tuple (extracted_text, list_of_headings).
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Error reading Markdown file {file_path}: {e}")
        return "", []

    md = MarkdownIt()
    html_content = md.render(content)
    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract text
    text_content = soup.get_text(separator=' ', strip=True)
    words = text_content.split()
    extracted_text = " ".join(words[:MAX_DOC_WORDS])

    # Extract H1, H2, H3 headings
    headings = []
    for heading_tag in soup.find_all(['h1', 'h2', 'h3']):
        headings.append(heading_tag.get_text(strip=True))
    
    logger.debug(f"Extracted from {file_path}: {len(words)} words (truncated to {len(extracted_text.split())}), {len(headings)} headings.")
    return extracted_text, headings

import yaml # PyYAML
import json

def parse_openapi_file(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Parses an OpenAPI/Swagger file (YAML or JSON) and extracts basic info.

    Args:
        file_path: Path to the potential OpenAPI/Swagger file.

    Returns:
        A dictionary with extracted info (e.g., title, version, summary) 
        or None if the file is not a recognized spec.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content_str = f.read()
        
        data: Optional[Dict[str, Any]] = None
        if file_path.endswith(('.yaml', '.yml')):
            try:
                data = yaml.safe_load(content_str)
            except yaml.YAMLError as e:
                logger.debug(f"Failed to parse YAML {file_path}: {e}")
                return None
        elif file_path.endswith('.json'):
            try:
                data = json.loads(content_str)
            except json.JSONDecodeError as e:
                logger.debug(f"Failed to parse JSON {file_path}: {e}")
                return None
        else:
            return None # Not a supported file type

        if not isinstance(data, dict): # Parsed content is not a dictionary
            logger.debug(f"File {file_path} did not parse into a dictionary.")
            return None

        # Check for OpenAPI/Swagger specific keys
        is_openapi_v3 = 'openapi' in data and isinstance(data.get('info'), dict) and isinstance(data.get('paths'), dict)
        is_swagger_v2 = 'swagger' in data and isinstance(data.get('info'), dict) and isinstance(data.get('paths'), dict)

        if not (is_openapi_v3 or is_swagger_v2):
            logger.debug(f"File {file_path} does not appear to be a valid OpenAPI/Swagger spec (missing key fields).")
            return None

        info = data.get('info', {})
        extracted_data = {
            "title": info.get('title', 'N/A'),
            "version": info.get('version', 'N/A'),
            "description": info.get('description', '').strip(),
            "summary": info.get('summary', '').strip(), # OpenAPI 3.1 specific
            "source_file": os.path.basename(file_path)
        }
        
        # Prefer description, fallback to summary if description is empty
        if not extracted_data["description"] and extracted_data["summary"]:
            extracted_data["description"] = extracted_data["summary"]
        
        # Truncate description if too long for our purposes
        if len(extracted_data["description"]) > 1000: # Arbitrary limit for preview
            extracted_data["description"] = extracted_data["description"][:1000] + "..."

        logger.info(f"Successfully parsed OpenAPI/Swagger spec: {file_path}")
        return extracted_data

    except Exception as e:
        logger.error(f"Error processing OpenAPI file {file_path}: {e}")
        return None

def find_code_files(repo_path: str) -> Dict[str, list[str]]:
    """
    Finds relevant source code files in the repository.
    Currently focuses on Python files (*.py).

    Args:
        repo_path: The root path of the unzipped repository.

    Returns:
        A dictionary with keys like 'python' containing lists of file paths.
    """
    python_files = []

    # Find all .py files, excluding common virtual environment folders
    # A more robust exclusion list might be needed for complex projects
    excluded_dirs_patterns = ["venv/", "env/", ".venv/", ".env/", "node_modules/", "__pycache__/"]

    for py_file_path in glob.glob(os.path.join(repo_path, "**", "*.py"), recursive=True):
        normalized_path = os.path.normpath(py_file_path)
        # Check if the path is within any of the excluded directory patterns
        is_excluded = False
        for pattern in excluded_dirs_patterns:
            # Check if 'pattern' (e.g., 'venv/') is part of the path segments
            # This basic check might need refinement for paths like /path/to/some_venv/file.py
            # A more robust way would be to check if normalized_path starts with os.path.join(repo_path, pattern_dir)
            # For simplicity here, we check if the pattern substring is in the path relative to repo_path
            relative_path = os.path.relpath(normalized_path, repo_path)
            if pattern.strip('/') in relative_path.split(os.sep):
                 is_excluded = True
                 logger.debug(f"Excluding '{normalized_path}' due to pattern '{pattern}'. Relative path: {relative_path}")
                 break
        
        if not is_excluded:
            python_files.append(normalized_path)
        
    python_files = sorted(list(set(python_files))) # Ensure uniqueness and order

    logger.info(f"Found {len(python_files)} potential Python files: {python_files if len(python_files) < 10 else str(python_files[:10]) + '...'}")

    return {
        "python": python_files,
        # Add other languages here if needed, e.g., "javascript": js_files
    }

import ast

# Define keywords for different categories of libraries
BIOMETRIC_KEYWORDS = ["face_recognition", "cv2", "dlib", "mediapipe"]
GPAI_KEYWORDS = ["openai", "transformers", "tensorflow", "torch", "keras", "pytorch_lightning", "langchain", "llama_index"]
REALTIME_STREAM_KEYWORDS = ["websockets", "socketio", "kafka", "pika", "aiohttp", "fastapi.WebSocket"]

class PythonCodeAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.signals = {
            "biometric_lib_detected": False,
            "gpai_lib_detected": False,
            "realtime_stream_lib_detected": False,
            "detected_libraries": set() # Store specific names of detected libs
        }

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._check_module_name(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._check_module_name(node.module)
        # Also check imported names if module itself is generic (e.g., from fastapi import WebSocket)
        # For simplicity, primary check is on module name.
        # for alias in node.names:
        # self._check_module_name(alias.name) # This might be too broad for some cases
        self.generic_visit(node)

    def _check_module_name(self, module_name: str):
        # Check against main module name, e.g., 'cv2' or 'face_recognition'
        # Sometimes imports are like 'tensorflow.keras', so check root.
        root_module = module_name.split('.')[0]

        if root_module in BIOMETRIC_KEYWORDS:
            self.signals["biometric_lib_detected"] = True
            self.signals["detected_libraries"].add(root_module)
            logger.debug(f"Biometric lib pattern '{root_module}' detected in {self.file_path}")

        if root_module in GPAI_KEYWORDS:
            self.signals["gpai_lib_detected"] = True
            self.signals["detected_libraries"].add(root_module)
            logger.debug(f"GPAI lib pattern '{root_module}' detected in {self.file_path}")

        if root_module in REALTIME_STREAM_KEYWORDS or module_name in REALTIME_STREAM_KEYWORDS:
            # Check full module_name too for specific cases like 'fastapi.WebSocket'
            self.signals["realtime_stream_lib_detected"] = True
            self.signals["detected_libraries"].add(module_name if module_name in REALTIME_STREAM_KEYWORDS else root_module)
            logger.debug(f"Real-time stream lib pattern '{module_name if module_name in REALTIME_STREAM_KEYWORDS else root_module}' detected in {self.file_path}")

async def analyze_python_code_ast(file_path: str) -> Dict[str, Any]:
    """
    Analyzes a single Python file using AST to find specific library imports.

    Args:
        file_path: The absolute path to the Python file.

    Returns:
        A dictionary containing signals like 'biometric_lib_detected', etc.
    """
    logger.debug(f"Analyzing Python file with AST: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        tree = ast.parse(source_code, filename=file_path)
        analyzer = PythonCodeAnalyzer(file_path)
        analyzer.visit(tree)
        # Convert set to list for JSON serialization if needed later, but fine for internal use
        # analyzer.signals["detected_libraries"] = list(analyzer.signals["detected_libraries"])
        return analyzer.signals
    except FileNotFoundError:
        logger.error(f"AST Analysis: File not found: {file_path}")
        return {"error": "File not found", "file_path": file_path}
    except SyntaxError as e:
        logger.warning(f"AST Analysis: Syntax error in {file_path}: {e}. Skipping file.")
        return {"error": f"Syntax error: {e.msg}", "file_path": file_path, "line": e.lineno, "offset": e.offset}
    except Exception as e:
        logger.error(f"AST Analysis: Error analyzing {file_path}: {e}")
        return {"error": str(e), "file_path": file_path}

import asyncio
from typing import List, Optional, Tuple, Dict, Any
from app.models import GrepSignalItem, CodeSignal, ChecklistItem

DEFAULT_GREP_PATTERN = r"(face_recognition|opencv|datetime\.now|deploy|real-time|stream)"
DEFAULT_GREP_EXTENSIONS = ["md", "yaml", "yml", "json", "py", "ts", "js"]

async def run_grep_search(
    directory_path: str,
    pattern: str = DEFAULT_GREP_PATTERN,
    file_extensions: List[str] = None
) -> List[GrepSignalItem]:
    """Runs grep command in the specified directory and parses the output."""
    if file_extensions is None:
        file_extensions = DEFAULT_GREP_EXTENSIONS

    signals: List[GrepSignalItem] = []
    
    include_args = []
    for ext in file_extensions:
        # Ensure ext is just the extension, e.g., 'py', not '.py'
        clean_ext = ext.lstrip('.')
        include_args.append(f"--include='*.{clean_ext}'")
    
    include_str = " ".join(include_args)
    
    # Command: grep -rniE --binary-files=without-match --include='*.py' ... 'pattern' .
    # We run it with cwd=directory_path so file paths in output are relative to repo root.
    cmd = f"grep -rniE --binary-files=without-match {include_str} '{pattern}' ."
    
    logger.info(f"Running grep in {directory_path} for pattern '{pattern}' with extensions {file_extensions}")
    logger.debug(f"Grep command: {cmd}")

    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=directory_path
    )
    stdout, stderr = await process.communicate()

    if process.returncode == 0:  # Grep found matches
        output = stdout.decode(errors='ignore').strip()
        for line in output.splitlines():
            parts = line.split(':', 2)  # Format: ./path/to/file.ext:line_num:content
            if len(parts) == 3:
                file_path = parts[0]
                if file_path.startswith('./'):
                    file_path = file_path[2:]  # Remove leading './'
                try:
                    line_number = int(parts[1])
                    line_content = parts[2]
                    signals.append(GrepSignalItem(file_path=file_path, line_number=line_number, line_content=line_content))
                except ValueError:
                    logger.warning(f"Could not parse line number from grep output: {line}")
            else:
                logger.warning(f"Could not parse grep output line (expected 3 parts): {line}")
        logger.info(f"Grep found {len(signals)} signals.")
    elif process.returncode == 1:  # Grep found no matches (normal)
        logger.info(f"Grep found no matches for pattern '{pattern}'.")
    else:  # Grep command itself failed
        error_message = stderr.decode(errors='ignore').strip()
        logger.error(f"Grep command failed with exit code {process.returncode}: {error_message}")
        # Depending on desired behavior, could raise an exception here

    return signals

DEFAULT_OBLIGATIONS_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'obligations.yaml')

def load_full_obligations_data(file_path: str = DEFAULT_OBLIGATIONS_PATH) -> Dict[str, Any]:
    """Loads the entire obligations YAML file and returns its content as a dictionary."""
    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                logger.error(f"Obligations file {file_path} did not parse into a dictionary.")
                return {}
            logger.info(f"Successfully loaded full obligations data from {file_path}.")
            return data
    except FileNotFoundError:
        logger.error(f"Obligations file not found at {file_path}. Returning empty data.")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing obligations YAML file {file_path}: {e}. Returning empty data.")
        return {}
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading obligations file {file_path}: {e}. Returning empty data.")
        return {}

def load_and_get_checklist_for_tier(tier: str, obligations_file_path: str = DEFAULT_OBLIGATIONS_PATH) -> List[ChecklistItem]:
    """Loads compliance checklist items for a specific risk tier from the YAML file."""
    yaml_key = TIER_TO_YAML_KEY_MAP.get(tier.lower())
    if not yaml_key:
        logger.warning(f"No YAML key mapping found for tier: {tier}. Returning empty checklist.")
        return []

    try:
        with open(obligations_file_path, 'r', encoding='utf-8') as f:
            all_obligations_data = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Obligations file not found at {obligations_file_path}. Returning empty checklist.")
        return []
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file {obligations_file_path}: {e}. Returning empty checklist.")
        return []

    tier_specific_obligations = all_obligations_data.get(yaml_key, {}).get("obligations", [])
    
    if not tier_specific_obligations:
        logger.info(f"No obligations found for tier '{tier}' (YAML key: '{yaml_key}'). Returning empty checklist.")
        return []

    checklist_items = []
    for item_data in tier_specific_obligations:
        try:
            checklist_item = ChecklistItem(
                id=item_data.get("id", "N/A"),
                title=item_data.get("title", "No title provided"),
                description=item_data.get("description", "No description provided"),
                reference_article=item_data.get("reference"), # 'reference' in YAML maps to 'reference_article'
                category_type=item_data.get("type") # 'type' in YAML maps to 'category_type'
            )
            checklist_items.append(checklist_item)
        except Exception as e: # Catch Pydantic validation errors or others
            logger.warning(f"Could not parse checklist item {item_data.get('id', 'Unknown ID')} for tier {tier}: {e}. Skipping item.")
            
    logger.info(f"Loaded {len(checklist_items)} checklist items for tier '{tier}'.")
    return checklist_items

# Map scanner tiers to YAML keys
TIER_TO_YAML_KEY_MAP = {
    "prohibited": "prohibited_ai_systems", # Assuming this key exists or will be added
    "high": "high_risk",
    "limited": "limited_risk",
    "minimal": "minimal_risk" # Or 'general_obligations_for_all_ai' if that's more appropriate for minimal
}
