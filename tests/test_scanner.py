import pytest
from unittest.mock import AsyncMock, MagicMock, call
import tempfile
import os
import shutil
from app.services.llm_service import LLMService
from app.scanner import scan_repo, resolve_repo_input
from app.models import (
    RepoInputModel, 
    RepoInfo, 
    ScanResultModel, 
    ChecklistItem, 
    CodeSignal,
    FuzzyMatchResult,
    RepositoryFile,
    CodeAnalysisResult
)
from app.config import settings
import io

@pytest.fixture
def mock_repo_input_url() -> RepoInputModel:
    return RepoInputModel(repo_url="https://github.com/example/repo")

@pytest.fixture
def mock_repo_input_details() -> RepoInputModel:
    return RepoInputModel(repo_details=RepoInfo(owner="example", repo="repo", branch="main"))

@pytest.fixture
def mock_llm_service_instance():
    service = MagicMock(spec=LLMService)
    service.summarize_documentation = AsyncMock(return_value=["LLM summary point 1", "Point 2"])
    service.classify_risk_with_llm = AsyncMock(return_value="high")
    service.is_openai_configured = MagicMock(return_value=True)
    return service

@pytest.fixture
def mock_db_service_instance():
    service = MagicMock()
    service.save_scan_result = AsyncMock(return_value="mock_db_id_123")
    return service

@pytest.fixture
def mock_scanner_dependencies(mocker, mock_llm_service_instance, mock_db_service_instance):
    mock_paths = {
        # Target: (path_to_patch, MockClass, autospec_boolean_or_default_True)
        'get_repo_archive_info': ('app.scanner.get_repo_archive_info', AsyncMock, False),
        'resolve_repo_input': ('app.scanner.resolve_repo_input', AsyncMock, False),
        'download_repo_zip': ('app.scanner.download_repo_zip', AsyncMock, False),
        'unzip_archive': ('app.scanner.unzip_archive', AsyncMock, False),
        'find_documentation_files': ('app.scanner.find_documentation_files', MagicMock, True),
        'extract_text_and_headings_from_markdown': ('app.scanner.extract_text_and_headings_from_markdown', MagicMock, True),
        'parse_openapi_file': ('app.scanner.parse_openapi_file', MagicMock, True),
        'LLMService': ('app.scanner.LLMService', MagicMock, True), # To mock the class instantiation
        'find_code_files': ('app.scanner.find_code_files', MagicMock, True),
        'run_grep_search': ('app.scanner.run_grep_search', AsyncMock, False),
        'determine_risk_tier': ('app.scanner.determine_risk_tier', AsyncMock, False),
        'load_full_obligations_data': ('app.scanner.load_full_obligations_data', MagicMock, True),
        'load_and_get_checklist_for_tier': ('app.scanner.load_and_get_checklist_for_tier', MagicMock, True),
        'upsert_obligation_documents': ('app.scanner.upsert_obligation_documents', AsyncMock, False),
        'upsert_repository_documents': ('app.scanner.upsert_repository_documents', AsyncMock, False),
        'find_matching_obligations_for_repo_doc': ('app.scanner.find_matching_obligations_for_repo_doc', AsyncMock, False),
        'os.path.exists': ('app.scanner.os.path.exists', MagicMock, True),
        'os.path.relpath': ('app.scanner.os.path.relpath', MagicMock, True), # Config, will be handled specially
        'tempfile.mkdtemp': ('app.scanner.tempfile.mkdtemp', MagicMock, True),
        'shutil.rmtree': ('app.scanner.shutil.rmtree', MagicMock, True),
        'analyze_python_code_ast': ('app.scanner.analyze_python_code_ast', MagicMock, False),
        'analyze_js_ts_code_ast': ('app.scanner.analyze_js_ts_code_ast', MagicMock, False),
    }

    mocks = {}
    for path_key, config_tuple in mock_paths.items():
        target_path = config_tuple[0]
        mock_class_to_use = config_tuple[1]
        autospec_setting_for_mock = config_tuple[2] # True or False as defined above
        
        if target_path == 'app.scanner.LLMService': # Special handling for mocking the class used for instantiation
            mocks[path_key] = mocker.patch(target_path, 
                                       return_value=mock_llm_service_instance, 
                                       autospec=autospec_setting_for_mock)
        elif path_key == 'os.path.relpath': # Special handling for os.path.relpath
            mocks[path_key] = mocker.patch(target_path, 
                                           side_effect=os.path.relpath, 
                                           autospec=True) # Keep autospec True for signature checking
        else:
            # Pass autospec to the constructor of the mock_class_to_use via new_callable's lambda
            # Need to capture loop variables correctly in lambda using default arguments
            mocks[path_key] = mocker.patch(target_path, 
                                       new_callable=lambda mc=mock_class_to_use, auto=autospec_setting_for_mock: mc(autospec=auto))

    # Store original os.path.relpath before patching
    original_os_path_relpath = os.path.relpath

    # Patch os.path.relpath first
    mocks['os.path.relpath'] = mocker.patch('os.path.relpath')
    # Then assign its side_effect using the original function
    mocks['os.path.relpath'].side_effect = lambda path, start: os.path.normpath(original_os_path_relpath(path, start))

    mocks['resolve_repo_input'].return_value = RepoInfo(owner="example", repo="repo", branch="main", commit_sha="mock_commit_sha")
    mocks['get_repo_archive_info'].return_value = ("main", "mock_commit_sha_from_archive_info")
    mocks['download_repo_zip'].return_value = ("/tmp/mock_repo.zip", "mock_commit_sha")
    mocks['unzip_archive'].return_value = "/tmp/unzipped_repo"
    mocks['find_documentation_files'].return_value = {'markdown': ['README.md'], 'openapi': ['api/openapi.json']}
    mocks['extract_text_and_headings_from_markdown'].return_value = ("Sample markdown text", ["Heading1"])
    mocks['parse_openapi_file'].return_value = {"info": {"title": "Test API"}} # Default return for parse_openapi_file
    mocks['LLMService'].return_value = mock_llm_service_instance
    mocks['find_code_files'].return_value = {'python': ['src/main.py'], 'javascript': [], 'typescript': []}
    mocks['run_grep_search'].return_value = [] # Default to no grep signals
    mocks['determine_risk_tier'].return_value = "minimal"
    mocks['load_full_obligations_data'].return_value = [
        {
            "id": "OBL001", 
            "title": "Test Obligation Title from Raw Data", 
            "description": "Test Obligation Description from Raw Data",
            "type": "General", # Assuming 'type' is the key in YAML for category_type
            "reference": "http://example.com/raw_obl001" # Assuming 'reference' for reference_article
        }
    ]
    mocks['load_and_get_checklist_for_tier'].return_value = [
        ChecklistItem(id="CHK001", title="Test Checklist Item 1 for minimal tier", description="Description for CHK001", category_type="Test Category", reference_article="http://example.com/chk001")
    ]
    mocks['upsert_obligation_documents'].return_value = ["obl_doc_id_1", "obl_doc_id_2"]
    mocks['upsert_repository_documents'].return_value = ["repo_doc_id_1"]
    mocks['find_matching_obligations_for_repo_doc'].return_value = [
        FuzzyMatchResult(
            obligation_id="OBL001",
            obligation_title="Sample Obligation Title",
            repo_content_source="README.md",
            repo_content_snippet="This is a snippet from the repository documentation related to the obligation.",
            similarity_score=0.85
        )
    ]
    mocks['os.path.exists'].return_value = True
    mocks['tempfile.mkdtemp'].return_value = "/mock/temp/mkdtemp_path"
    # shutil.rmtree is just a mock, no specific return value needed unless checked

    mock_file_contents_for_test = {}  # Scoped to this fixture instance (i.e., per test)
    mock_open_call_counts_for_test = {} # Scoped to this fixture instance

    class MinimalMockFile:
        def __init__(self, string_io_instance, file_path_str):
            self._sio = string_io_instance
            self.name = file_path_str
            self.closed = False

        def read(self, size=-1):
            if self.closed:
                raise ValueError("I/O operation on closed file.")
            return self._sio.read(size)

        def readlines(self, hint=-1):
            if self.closed:
                raise ValueError("I/O operation on closed file.")
            return self._sio.readlines(hint)

        def __iter__(self):
            if self.closed:
                raise ValueError("I/O operation on closed file.")
            return self._sio.__iter__()
        
        def seekable(self):
            return self._sio.seekable()

        def seek(self, offset, whence=0):
            if self.closed:
                raise ValueError("I/O operation on closed file.")
            return self._sio.seek(offset, whence)

        def tell(self):
            if self.closed:
                raise ValueError("I/O operation on closed file.")
            return self._sio.tell()

        def close(self):
            self._sio.close()
            self.closed = True

        def __enter__(self):
            if self.closed:
                raise ValueError("I/O operation on closed file.")
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.close()
            return False

    def open_side_effect_func_inner(path, mode='r', encoding=None, errors=None):
        path_str = str(path) 
        current_call_count = mock_open_call_counts_for_test.get(path_str, 0) + 1
        mock_open_call_counts_for_test[path_str] = current_call_count

        if path_str not in mock_file_contents_for_test:
            raise FileNotFoundError(f"[Mock] File not found: {path_str}")

        content = mock_file_contents_for_test[path_str]
        
        string_io_obj = io.StringIO(str(content))
        return MinimalMockFile(string_io_obj, path_str)

    mocks['open_patcher'] = mocker.patch('builtins.open', side_effect=open_side_effect_func_inner)
    mocks['_mock_file_contents_dict'] = mock_file_contents_for_test 
    mocks['_mock_open_call_counts_view'] = mock_open_call_counts_for_test

    mock_llm_service_instance.get_llm_summary.return_value = ["LLM summary point 1", "Point 2"]

    return mocks

@pytest.mark.asyncio
async def test_scan_repo_successful_run_with_fuzzy_matches(mocker, mock_scanner_dependencies, mock_repo_input_url, mock_llm_service_instance):
    mock_scanner_dependencies['find_matching_obligations_for_repo_doc'].return_value = [
        FuzzyMatchResult(
            obligation_id="OBL001",
            obligation_title="Test Obligation",
            repo_content_source="README.md", # This will be overwritten by the actual source in the loop
            repo_content_snippet="relevant snippet...",
            similarity_score=0.85
        )
    ]
    mock_llm_service_instance.is_openai_configured.return_value = True # Ensure LLM is considered configured
    mock_llm_service_instance.summarize_documentation.return_value = ["LLM summary for fuzzy match test"]

    mock_mkdtemp_path = str(mock_scanner_dependencies['tempfile.mkdtemp'].return_value)

    mock_scanner_dependencies['_mock_file_contents_dict'].update({
        os.path.join(mock_mkdtemp_path, "README.md"): "Test Readme with fuzzy match target",
        os.path.join(mock_mkdtemp_path, "src", "main.py"): "print('hello world')",
        os.path.join(mock_mkdtemp_path, "api", "openapi.json"): '{"openapi":"3.0.0"}'
    })

    mock_scanner_dependencies['find_documentation_files'].return_value = {
        'markdown': [os.path.join(mock_mkdtemp_path, "README.md")],
        'openapi': [os.path.join(mock_mkdtemp_path, "api", "openapi.json")]
    }
    mock_scanner_dependencies['find_code_files'].return_value = {
        'python': [os.path.join(mock_mkdtemp_path, "src", "main.py")],
        'javascript': [], 'typescript': []
    }
    mock_scanner_dependencies['analyze_python_code_ast'].return_value = CodeAnalysisResult(uses_gpai=False)

    result = await scan_repo(mock_repo_input_url)

    assert result is not None
    assert len(result.fuzzy_matches) == 3
    assert result.fuzzy_matches[0].obligation_id == "OBL001"
    assert result.doc_summary == ["LLM summary for fuzzy match test"]

    expected_readme_path = os.path.join(mock_mkdtemp_path, "README.md")
    expected_py_path = os.path.join(mock_mkdtemp_path, "src", "main.py")
    expected_openapi_path = os.path.join(mock_mkdtemp_path, "api", "openapi.json")

    # Check that open was called for each file type with 'ignore'
    mock_scanner_dependencies['open_patcher'].assert_any_call(expected_readme_path, 'r', encoding='utf-8', errors='ignore')
    mock_scanner_dependencies['open_patcher'].assert_any_call(expected_py_path, 'r', encoding='utf-8', errors='ignore')
    mock_scanner_dependencies['open_patcher'].assert_any_call(expected_openapi_path, 'r', encoding='utf-8', errors='ignore')

    mock_scanner_dependencies['upsert_obligation_documents'].assert_called_once_with(mock_scanner_dependencies['load_full_obligations_data'].return_value)
    mock_scanner_dependencies['upsert_repository_documents'].assert_called_once()
    args, _ = mock_scanner_dependencies['upsert_repository_documents'].call_args
    repo_files_arg = args[0]
    assert len(repo_files_arg) >= 1 # README, python, openapi

    mock_scanner_dependencies['find_matching_obligations_for_repo_doc'].assert_called()


@pytest.mark.asyncio
async def test_scan_repo_llm_summary_failure(mocker, mock_scanner_dependencies, mock_repo_input_url, mock_llm_service_instance):
    mock_mkdtemp_path = str(mock_scanner_dependencies['tempfile.mkdtemp'].return_value)
    mock_scanner_dependencies['determine_risk_tier'].return_value = "minimal" # Default rule-based tier
    
    mock_scanner_dependencies['_mock_file_contents_dict'].update({
        os.path.join(mock_mkdtemp_path, "README.md"): "default fallback content"
    })
    mock_scanner_dependencies['find_documentation_files'].return_value = {
        'markdown': [os.path.join(mock_mkdtemp_path, "README.md")], 'openapi': []
    }
    mock_scanner_dependencies['find_code_files'].return_value = {'python': [], 'javascript': [], 'typescript': []}

    mock_llm_service_instance.is_openai_configured.return_value = True
    mock_llm_service_instance.summarize_documentation.return_value = ["LLM summary for fallback test"]

    await scan_repo(mock_repo_input_url)
    mock_scanner_dependencies['shutil.rmtree'].assert_called_once_with(mock_mkdtemp_path)


@pytest.mark.asyncio
async def test_scan_repo_vector_processing_calls(mocker, mock_scanner_dependencies, mock_repo_input_url, mock_db_service_instance):
    mock_mkdtemp_path = str(mock_scanner_dependencies['tempfile.mkdtemp'].return_value)

    mock_scanner_dependencies['find_documentation_files'].return_value = {
        'markdown': [os.path.join(mock_mkdtemp_path, "README.md")],
        'openapi': [os.path.join(mock_mkdtemp_path, "api", "openapi.json")]
    }
    mock_scanner_dependencies['extract_text_and_headings_from_markdown'].return_value = ("# Test Readme", ['Test Readme'])
    mock_scanner_dependencies['parse_openapi_file'].return_value = {
        "info": {"title": "API for vector test"},
        "paths": {"/test_endpoint": {}}
    }
    mock_scanner_dependencies['find_code_files'].return_value = {
        'python': [os.path.join(mock_mkdtemp_path, "src", "main.py")],
        'javascript': [], 'typescript': []
    }
    mock_scanner_dependencies['analyze_python_code_ast'].return_value = CodeAnalysisResult(uses_gpai=False)

    mock_scanner_dependencies['_mock_file_contents_dict'].update({
        os.path.join(mock_mkdtemp_path, "README.md"): "Markdown content for vector test",
        os.path.join(mock_mkdtemp_path, "src", "main.py"): "Python content for vector test",
        os.path.join(mock_mkdtemp_path, "api", "openapi.json"): '{"openapi": "3.0.0", "info": {"title": "API for vector test"}}'
    })

    result = await scan_repo(mock_repo_input_url)

    mock_scanner_dependencies['upsert_obligation_documents'].assert_called_once()
    mock_scanner_dependencies['upsert_repository_documents'].assert_called_once()

    expected_readme_path = os.path.join(mock_mkdtemp_path, "README.md")
    expected_py_path = os.path.join(mock_mkdtemp_path, "src", "main.py")
    expected_openapi_path = os.path.join(mock_mkdtemp_path, "api", "openapi.json")

    mock_scanner_dependencies['open_patcher'].assert_any_call(expected_readme_path, 'r', encoding='utf-8', errors='ignore')
    mock_scanner_dependencies['open_patcher'].assert_any_call(expected_py_path, 'r', encoding='utf-8', errors='ignore')
    mock_scanner_dependencies['open_patcher'].assert_any_call(expected_openapi_path, 'r', encoding='utf-8', errors='ignore')

    args, _ = mock_scanner_dependencies['upsert_repository_documents'].call_args
    repo_files_arg = args[0]
    assert len(repo_files_arg) == 3
    paths_in_arg = sorted([item.path for item in repo_files_arg])
    expected_paths = sorted([
        "README.md",
        os.path.join("api", "openapi.json"),
        os.path.join("src", "main.py")
    ])
    assert paths_in_arg == expected_paths

    mock_scanner_dependencies['find_matching_obligations_for_repo_doc'].assert_called()


@pytest.mark.asyncio
async def test_scan_repo_no_python_files(mocker, mock_scanner_dependencies, mock_repo_input_url):
    mock_mkdtemp_path = str(mock_scanner_dependencies['tempfile.mkdtemp'].return_value)
    mock_scanner_dependencies['find_code_files'].return_value = {'python': [], 'javascript': [], 'typescript': []}
    
    mock_scanner_dependencies['_mock_file_contents_dict'].update({
        os.path.join(mock_mkdtemp_path, "README.md"): "default content for no python test"
    })
    mock_scanner_dependencies['find_documentation_files'].return_value = {
        'markdown': [os.path.join(mock_mkdtemp_path, "README.md")], 'openapi': []
    }

    result = await scan_repo(mock_repo_input_url)

    assert result.code_signals == CodeSignal() # Expect default CodeSignal if no code files found
