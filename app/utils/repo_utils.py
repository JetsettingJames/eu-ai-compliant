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
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def get_repo_archive_info(repo_url: str) -> Dict[str, Any]:
    """
    Extract repository information from a GitHub repository URL.
    
    Args:
        repo_url: GitHub repository URL
        
    Returns:
        Dictionary containing repository information (owner, repo name, etc.)
    """
    logger.info(f"Extracting repository information from URL: {repo_url}")
    
    # Parse the URL
    parsed_url = urlparse(repo_url)
    path_parts = parsed_url.path.strip('/').split('/')
    
    if len(path_parts) < 2:
        logger.error(f"Invalid repository URL format: {repo_url}")
        raise ValueError(f"Invalid repository URL format: {repo_url}")
    
    owner = path_parts[0]
    repo_name = path_parts[1]
    branch = "main"  # Default to main branch
    
    # If there's a branch specified in the URL
    if len(path_parts) > 3 and path_parts[2] == "tree":
        branch = path_parts[3]
    
    archive_url = f"https://github.com/{owner}/{repo_name}/archive/refs/heads/{branch}.zip"
    
    return {
        "owner": owner,
        "repo_name": repo_name,
        "branch": branch,
        "archive_url": archive_url,
        "full_name": f"{owner}/{repo_name}"
    }

def download_repo_zip(archive_url: str) -> Optional[str]:
    """
    Download a repository ZIP archive from GitHub.
    
    Args:
        archive_url: URL to the repository ZIP archive
        
    Returns:
        Path to the downloaded ZIP file
    """
    logger.info(f"Downloading repository archive from: {archive_url}")
    
    try:
        # Create a temporary file to store the ZIP
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        temp_file.close()
        
        # Download the ZIP file
        response = requests.get(archive_url, stream=True)
        response.raise_for_status()
        
        with open(temp_file.name, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        logger.info(f"Repository archive downloaded to: {temp_file.name}")
        return temp_file.name
    except Exception as e:
        logger.error(f"Error downloading repository archive: {str(e)}")
        return None

def unzip_archive(zip_path: str) -> Optional[str]:
    """
    Extract a ZIP archive to a temporary directory.
    
    Args:
        zip_path: Path to the ZIP archive
        
    Returns:
        Path to the extracted directory
    """
    logger.info(f"Extracting ZIP archive: {zip_path}")
    
    try:
        # Create a temporary directory to extract the ZIP
        temp_dir = tempfile.mkdtemp()
        
        # Extract the ZIP file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Get the root directory of the extracted content
        extracted_dirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
        if not extracted_dirs:
            logger.error("No directories found in the extracted ZIP archive")
            return None
        
        # The repository is usually extracted to a single directory
        repo_dir = os.path.join(temp_dir, extracted_dirs[0])
        logger.info(f"Repository extracted to: {repo_dir}")
        return repo_dir
    except Exception as e:
        logger.error(f"Error extracting ZIP archive: {str(e)}")
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
