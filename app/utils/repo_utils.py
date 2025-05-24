"""
Repository Utilities

This module provides utilities for working with Git repositories,
including downloading, extracting, and analyzing repository content.
"""
import os
import tempfile
import zipfile
import requests
import logging
from typing import Dict, Any, List, Optional, Tuple
from ..models import RepoInfo
from urllib.parse import urlparse
import httpx

logger = logging.getLogger(__name__)

GITHUB_API_BASE_URL = "https://api.github.com"

async def fetch_github_repo_branch_info(owner: str, repo_name: str, branch_name: Optional[str] = None, token: Optional[str] = None) -> Tuple[str, str]:
    """
    Fetches the specified (or default) branch name and its latest commit SHA for a GitHub repository.

    Args:
        owner: The owner of the repository.
        repo_name: The name of the repository.
        branch_name: Optional specific branch name. If None, the default branch is used.
        token: Optional GitHub personal access token for authentication.

    Returns:
        A tuple (actual_branch_name, commit_sha).

    Raises:
        ValueError: If the repository or branch is not found or other API errors occur.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(headers=headers, timeout=60.0) as client:
        actual_branch_name = branch_name
        if not actual_branch_name:
            # Fetch repository details to get the default branch
            repo_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo_name}"
            logger.info(f"Fetching repo details to find default branch: {repo_url}")
            try:
                response = await client.get(repo_url)
                response.raise_for_status() # Raise an exception for 4XX or 5XX status codes
                repo_data = response.json()
                actual_branch_name = repo_data.get("default_branch")
                if not actual_branch_name:
                    raise ValueError(f"Could not determine default branch for {owner}/{repo_name}. Response: {repo_data}")
                logger.info(f"Default branch for {owner}/{repo_name} is {actual_branch_name}")
            except httpx.HTTPStatusError as e:
                logger.error(f"GitHub API error fetching repo details for {owner}/{repo_name}: {e.response.status_code} - {e.response.text}")
                raise ValueError(f"Could not fetch repository details for {owner}/{repo_name}. Status: {e.response.status_code}. Error: {e.response.text}") from e
            except Exception as e:
                logger.error(f"Unexpected error fetching repo details for {owner}/{repo_name}: {e}")
                raise ValueError(f"Unexpected error fetching repository details for {owner}/{repo_name}: {e}") from e

        # Fetch branch details to get the commit SHA
        branch_url = f"{GITHUB_API_BASE_URL}/repos/{owner}/{repo_name}/branches/{actual_branch_name}"
        logger.info(f"Fetching branch details for {actual_branch_name}: {branch_url}")
        try:
            response = await client.get(branch_url)
            response.raise_for_status()
            branch_data = response.json()
            commit_sha = branch_data.get("commit", {}).get("sha")
            if not commit_sha:
                raise ValueError(f"Could not get commit SHA for branch {actual_branch_name} of {owner}/{repo_name}. Response: {branch_data}")
            logger.info(f"Latest commit SHA for {owner}/{repo_name} on branch {actual_branch_name} is {commit_sha}")
            return actual_branch_name, commit_sha
        except httpx.HTTPStatusError as e:
            logger.error(f"GitHub API error fetching branch details for {owner}/{repo_name}/{actual_branch_name}: {e.response.status_code} - {e.response.text}")
            raise ValueError(f"Could not fetch branch details for {owner}/{repo_name}/{actual_branch_name}. Status: {e.response.status_code}. Error: {e.response.text}") from e
        except Exception as e:
            logger.error(f"Unexpected error fetching branch details for {owner}/{repo_name}/{actual_branch_name}: {e}")
            raise ValueError(f"Unexpected error fetching branch details for {owner}/{repo_name}/{actual_branch_name}: {e}") from e

async def get_repo_archive_info(repo_details_obj: RepoInfo, token: Optional[str]) -> Tuple[str, str, str]:
    """
    Fetches the target branch name (resolving default if necessary), its latest commit SHA,
    and constructs the archive download URL.

    Args:
        repo_details_obj: RepoInfo object with owner and repo, and optionally branch.
        token: GitHub API token.

    Returns:
        A tuple (archive_url, target_branch_name, commit_sha).
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
        # 1. Determine the branch to use (default or specified)
        target_branch_name = repo_details_obj.branch
        if not target_branch_name:
            api_repo_url = f"https://api.github.com/repos/{repo_details_obj.owner}/{repo_details_obj.repo}"
            logger.info(f"Fetching default branch for {repo_details_obj.owner}/{repo_details_obj.repo} from {api_repo_url}")
            try:
                response = await client.get(api_repo_url)
                response.raise_for_status() # Raise an exception for HTTP errors
                repo_data = response.json()
                target_branch_name = repo_data.get("default_branch")
                if not target_branch_name:
                    raise ValueError(f"Could not determine default branch for {repo_details_obj.owner}/{repo_details_obj.repo}")
                logger.info(f"Default branch for {repo_details_obj.owner}/{repo_details_obj.repo} is {target_branch_name}")
            except httpx.HTTPStatusError as e:
                logger.error(f"GitHub API error fetching repo details: {e.response.status_code} - {e.response.text}")
                raise ValueError(f"Failed to fetch repo details for {repo_details_obj.owner}/{repo_details_obj.repo}: {e.response.status_code}") from e
            except Exception as e:
                logger.error(f"Error determining default branch: {e}")
                raise

        # 2. Get the commit SHA for the target branch
        branch_url = f"https://api.github.com/repos/{repo_details_obj.owner}/{repo_details_obj.repo}/branches/{target_branch_name}"
        logger.info(f"Fetching commit SHA for branch '{target_branch_name}' from {branch_url}")
        try:
            response = await client.get(branch_url)
            response.raise_for_status()
            branch_data = response.json()
            commit_sha = branch_data.get("commit", {}).get("sha")
            if not commit_sha:
                raise ValueError(f"Could not determine commit SHA for branch {target_branch_name}")
            logger.info(f"Commit SHA for {repo_details_obj.owner}/{repo_details_obj.repo}@{target_branch_name} is {commit_sha}")
            
            archive_download_url = f"https://github.com/{repo_details_obj.owner}/{repo_details_obj.repo}/archive/{commit_sha}.zip"
            logger.info(f"Archive download URL for {repo_details_obj.owner}/{repo_details_obj.repo}@{commit_sha} is {archive_download_url}")
            
            return archive_download_url, target_branch_name, commit_sha
        except httpx.HTTPStatusError as e:
            logger.error(f"GitHub API error fetching branch details: {e.response.status_code} - {e.response.text}")
            raise ValueError(f"Failed to fetch branch details for {target_branch_name}: {e.response.status_code}") from e
        except Exception as e:
            logger.error(f"Error determining commit SHA: {e}")
            raise

async def download_repo_zip(archive_url: str, token: Optional[str] = None) -> Optional[str]:
    """
    Download a repository ZIP archive from GitHub asynchronously.
    
    Args:
        archive_url: URL to the repository ZIP archive
        token: Optional GitHub personal access token for authentication.
        
    Returns:
        Path to the downloaded ZIP file, or None if an error occurs.
    """
    logger.info(f"Downloading repository archive from: {archive_url}")
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        logger.info("Using GitHub token for download.")
    else:
        logger.info("No GitHub token provided for download.")

    temp_file = None # Initialize to ensure it's defined in finally block
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")

        async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=60.0) as client:
            async with client.stream("GET", archive_url) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    temp_file.write(chunk)
        
        temp_file.close()
        logger.info(f"Repository archive downloaded to: {temp_file.name}")
        return temp_file.name
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error downloading repository archive {archive_url}: {e.response.status_code} - {e.response.text}")
        if temp_file and hasattr(temp_file, 'name') and os.path.exists(temp_file.name):
            if not temp_file.closed:
                temp_file.close()
            os.remove(temp_file.name) # Clean up empty/partial file
        return None
    except Exception as e:
        logger.error(f"Error downloading repository archive {archive_url}: {str(e)}")
        if temp_file and hasattr(temp_file, 'name') and os.path.exists(temp_file.name):
             if not temp_file.closed:
                temp_file.close()
             os.remove(temp_file.name) # Clean up
        return None
    finally:
        # Ensure the file is closed if it was opened, especially if an error occurred before explicit close
        if temp_file and hasattr(temp_file, 'name') and not temp_file.closed:
            try:
                temp_file.close()
                logger.info(f"Ensured temporary file {temp_file.name} is closed in finally block.")
            except Exception as e_close:
                logger.error(f"Error closing temp_file {temp_file.name} in finally block: {e_close}")


def unzip_archive(zip_path: str, extract_to_dir: str) -> Optional[str]:
    """
    Extract a ZIP archive to a specified directory.
    
    Args:
        zip_path: Path to the ZIP archive
        extract_to_dir: Directory to extract the archive contents into.
        
    Returns:
        Path to the directory containing the extracted repository files, 
        typically a single sub-directory within extract_to_dir.
        Returns None if an error occurs.
    """
    logger.info(f"Extracting ZIP archive: {zip_path} to {extract_to_dir}")
    
    try:
        # Ensure the extraction directory exists
        os.makedirs(extract_to_dir, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Check for zip bomb (very basic check: too many files or too large individual files)
            # A more robust check would inspect total uncompressed size if possible before extraction.
            num_files = len(zip_ref.infolist())
            if num_files > 20000: # Arbitrary limit for number of files
                logger.error(f"Zip bomb detected? Archive contains too many files: {num_files}")
                return None
            
            # Check total size (approximate, as this is compressed size sum)
            total_size_compressed = sum(file.file_size for file in zip_ref.infolist())
            if total_size_compressed > 500 * 1024 * 1024: # 500 MB compressed limit
                 logger.error(f"Zip bomb detected? Archive total compressed size too large: {total_size_compressed / (1024*1024):.2f} MB")
                 return None

            zip_ref.extractall(extract_to_dir)
        
        # GitHub archives usually extract to a single directory named like 'reponame-commitsha'
        # We need to find this directory within extract_to_dir.
        extracted_items = os.listdir(extract_to_dir)
        if not extracted_items:
            logger.error(f"No items found in the extraction directory: {extract_to_dir} after unzipping {zip_path}")
            return None

        # Assume the first directory found is the root of the unzipped repo
        # This might need to be more robust if there could be multiple or no directories.
        potential_repo_root = None
        for item in extracted_items:
            item_path = os.path.join(extract_to_dir, item)
            if os.path.isdir(item_path):
                potential_repo_root = item_path
                break
        
        if not potential_repo_root:
            logger.error(f"No sub-directory found in {extract_to_dir} after unzipping. Extracted items: {extracted_items}")
            return None

        logger.info(f"Repository extracted to: {potential_repo_root}")
        return potential_repo_root
    except zipfile.BadZipFile:
        logger.error(f"Bad ZIP file: {zip_path}")
        return None
    except Exception as e:
        logger.error(f"Error extracting ZIP archive {zip_path} to {extract_to_dir}: {str(e)}")
        return None


def find_documentation_files(repo_dir: str) -> Tuple[List[str], List[str]]:
    """
    Find documentation files (Markdown, OpenAPI) in a repository.
    
    Args:
        repo_dir: Path to the repository directory
        
    Returns:
        Tuple of (markdown_files, openapi_files) relative to repo_dir
    """
    logger.info(f"Finding documentation files in: {repo_dir}")
    
    markdown_files = []
    openapi_files = []
    
    for root, _, files in os.walk(repo_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, repo_dir)
            
            # Skip hidden files and directories
            if any(part.startswith('.') for part in rel_path.split(os.sep)):
                continue
            
            # Find Markdown files
            if file.lower().endswith(('.md', '.markdown')):
                markdown_files.append(rel_path)
            
            # Find OpenAPI files
            if file.lower().endswith(('.yaml', '.yml', '.json')) and ('openapi' in file.lower() or 'swagger' in file.lower()):
                openapi_files.append(rel_path)
    
    logger.info(f"Found {len(markdown_files)} Markdown files and {len(openapi_files)} OpenAPI files")
    return markdown_files, openapi_files

def extract_text_and_headings_from_markdown(file_path: str) -> Tuple[str, List[str]]:
    """
    Extract text and headings from a Markdown file.
    
    Args:
        file_path: Path to the Markdown file
        
    Returns:
        Tuple of (full_text, headings)
    """
    logger.info(f"Extracting text and headings from Markdown file: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract headings (lines starting with #)
        headings = []
        for line in content.split('\n'):
            if line.strip().startswith('#'):
                headings.append(line.strip())
        
        logger.info(f"Extracted {len(headings)} headings from Markdown file")
        return content, headings
    except Exception as e:
        logger.error(f"Error extracting text from Markdown file: {str(e)}")
        return "", []

def parse_openapi_file(file_path: str) -> Dict[str, Any]:
    """
    Parse an OpenAPI specification file.
    
    Args:
        file_path: Path to the OpenAPI file
        
    Returns:
        Dictionary containing OpenAPI specification information
    """
    logger.info(f"Parsing OpenAPI file: {file_path}")
    
    try:
        import yaml
        import json
        
        if file_path.lower().endswith(('.yaml', '.yml')):
            with open(file_path, 'r', encoding='utf-8') as f:
                spec = yaml.safe_load(f)
        else:  # JSON file
            with open(file_path, 'r', encoding='utf-8') as f:
                spec = json.load(f)
        
        # Extract basic information
        info = spec.get('info', {})
        paths = spec.get('paths', {})
        
        summary = {
            'title': info.get('title', 'Unknown API'),
            'version': info.get('version', 'Unknown'),
            'description': info.get('description', ''),
            'endpoint_count': len(paths),
            'endpoints': list(paths.keys())
        }
        
        logger.info(f"Parsed OpenAPI file with {summary['endpoint_count']} endpoints")
        return summary
    except Exception as e:
        logger.error(f"Error parsing OpenAPI file: {str(e)}")
        return {}

def find_code_files(repo_dir: str) -> Dict[str, List[str]]:
    """
    Find code files in a repository by extension.
    
    Args:
        repo_dir: Path to the repository directory
        
    Returns:
        Dictionary mapping language to list of file paths relative to repo_dir
    """
    logger.info(f"Finding code files in: {repo_dir}")
    
    code_files = {
        'python': [],
        'javascript': [],
        'typescript': [],
        'java': [],
        'csharp': [],
        'go': [],
        'rust': [],
        'other': []
    }
    
    extensions = {
        'python': ['.py'],
        'javascript': ['.js', '.jsx'],
        'typescript': ['.ts', '.tsx'],
        'java': ['.java'],
        'csharp': ['.cs'],
        'go': ['.go'],
        'rust': ['.rs']
    }
    
    for root, _, files in os.walk(repo_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, repo_dir)
            
            # Skip hidden files and directories
            if any(part.startswith('.') for part in rel_path.split(os.sep)):
                continue
            
            # Skip node_modules, vendor, and other dependency directories
            if any(part in ['node_modules', 'vendor', 'dist', 'build', 'target'] for part in rel_path.split(os.sep)):
                continue
            
            # Categorize by extension
            file_ext = os.path.splitext(file)[1].lower()
            categorized = False
            
            for lang, exts in extensions.items():
                if file_ext in exts:
                    code_files[lang].append(rel_path)
                    categorized = True
                    break
            
            # Categorize other code files
            if not categorized and file_ext in ['.rb', '.php', '.swift', '.kt', '.cpp', '.c', '.h', '.hpp']:
                code_files['other'].append(rel_path)
    
    # Count total files
    total_files = sum(len(files) for files in code_files.values())
    logger.info(f"Found {total_files} code files across {len(code_files)} languages")
    return code_files

def run_grep_search(repo_dir: str, patterns: List[str]) -> List[Dict[str, Any]]:
    """
    Run a grep-like search for patterns in repository files.
    
    Args:
        repo_dir: Path to the repository directory
        patterns: List of patterns to search for
        
    Returns:
        List of dictionaries containing match information
    """
    logger.info(f"Running grep search in {repo_dir} for {len(patterns)} patterns")
    
    results = []
    
    try:
        for root, _, files in os.walk(repo_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_dir)
                
                # Skip binary files, hidden files, and directories
                if any(part.startswith('.') for part in rel_path.split(os.sep)):
                    continue
                
                # Skip large files and binary files
                try:
                    if os.path.getsize(file_path) > 1024 * 1024:  # Skip files larger than 1MB
                        continue
                    
                    # Try to open the file as text
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                except (UnicodeDecodeError, IOError):
                    continue  # Skip binary files or files that can't be opened
                
                # Search for patterns
                for line_num, line in enumerate(lines, 1):
                    for pattern in patterns:
                        if pattern.lower() in line.lower():
                            results.append({
                                'file_path': rel_path,
                                'line_number': line_num,
                                'line_content': line.strip(),
                                'pattern': pattern
                            })
        
        logger.info(f"Found {len(results)} matches for grep patterns")
        return results
    except Exception as e:
        logger.error(f"Error running grep search: {str(e)}")
        return []

def read_file_content(file_path: str) -> str:
    """
    Read and return the content of a file as a string.

    Args:
        file_path: The absolute path to the file.

    Returns:
        The content of the file as a string.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If an error occurs during file reading.
    """
    logger.debug(f"Reading content from file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except UnicodeDecodeError as e:
        logger.warning(f"UnicodeDecodeError reading {file_path}, trying with 'latin-1': {e}")
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
            return content
        except Exception as e_inner:
            logger.error(f"Error reading file {file_path} even with latin-1: {e_inner}")
            raise IOError(f"Could not read file {file_path}: {e_inner}") from e_inner
    except IOError as e:
        logger.error(f"IOError reading file {file_path}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error reading file {file_path}: {e}")
        raise IOError(f"Unexpected error reading file {file_path}: {e}") from e
