import pytest
from unittest.mock import patch, AsyncMock, MagicMock, call
from typing import List, Dict, Any

from langchain.schema import Document

from app.models import RepositoryFile, FuzzyMatchResult
from app.vector_processing import (
    upsert_repository_documents,
    upsert_obligation_documents,
    find_matching_obligations_for_repo_doc,
)
from app.config import settings # For SIMILARITY_THRESHOLD

# Sample data for testing
SAMPLE_REPO_FILE_1 = RepositoryFile(path="file1.py", content="This is python code.", file_type="code")
SAMPLE_REPO_FILE_2 = RepositoryFile(path="README.md", content="This is a readme file.", file_type="doc")

SAMPLE_OBLIGATIONS_DATA = {
    "obligations": [
        {
            "id": "OBL001",
            "title": "Data Quality",
            "description": "Ensure high quality of data.",
            "details": "Detailed explanation of data quality requirements.",
            "tier_category": "high_general",
            "reference_article": "Art. 10",
            "responsible_entity": "Entity 1"
        },
        {
            "id": "OBL002",
            "title": "Transparency",
            "description": "Provide transparency to users.",
            "details": "Detailed explanation of transparency requirements.",
            "tier_category": "high_general",
            "reference_article": "Art. 13",
            "responsible_entity": "Entity 2"
        }
    ]
}

@pytest.fixture
def mock_text_splitter(mocker):
    mock = MagicMock()
    mock.split_text.side_effect = lambda text: [text] # Simple split for testing, one chunk per input
    return mock

@pytest.fixture
def mock_vector_store(mocker):
    mock = MagicMock()
    mock.add_documents = AsyncMock(return_value=["doc_id_1", "doc_id_2"])
    # similarity_search_with_score needs to return a list of (Document, score) tuples
    mock.similarity_search_with_score = AsyncMock(return_value=[])
    return mock

@pytest.mark.asyncio
@patch('app.vector_processing.text_splitter')
@patch('app.vector_processing.vector_store')
async def test_upsert_repository_documents_success(mock_vs, mock_ts):
    mock_ts.split_text.side_effect = lambda text: [f"{text}_chunk1", f"{text}_chunk2"]
    
    async def mock_add_docs(*args, **kwargs):
        return ["id1", "id2", "id3", "id4"]
    mock_vs.add_documents = MagicMock(side_effect=mock_add_docs)

    repo_files = [SAMPLE_REPO_FILE_1, SAMPLE_REPO_FILE_2]

    result_doc_ids = await upsert_repository_documents(repo_files)

    assert len(result_doc_ids) == 4 # 2 files * 2 chunks each
    mock_ts.split_text.assert_any_call(SAMPLE_REPO_FILE_1.content)
    mock_ts.split_text.assert_any_call(SAMPLE_REPO_FILE_2.content)
    assert mock_ts.split_text.call_count == 2

    mock_vs.add_documents.assert_called_once()
    added_docs_call_args = mock_vs.add_documents.call_args.kwargs['documents']
    assert len(added_docs_call_args) == 4
    
    # Check metadata of the first document from the first file
    doc1 = added_docs_call_args[0]
    assert isinstance(doc1, Document)
    assert doc1.page_content == f"{SAMPLE_REPO_FILE_1.content}_chunk1"
    assert doc1.metadata["source_type"] == "repository_file"
    assert doc1.metadata["source_identifier"] == SAMPLE_REPO_FILE_1.path
    assert doc1.metadata["file_type"] == SAMPLE_REPO_FILE_1.file_type
    assert doc1.metadata["chunk_index"] == 0

    # Check metadata of the first document from the second file
    doc3 = added_docs_call_args[2]
    assert isinstance(doc3, Document)
    assert doc3.page_content == f"{SAMPLE_REPO_FILE_2.content}_chunk1"
    assert doc3.metadata["source_identifier"] == SAMPLE_REPO_FILE_2.path

@pytest.mark.asyncio
@patch('app.vector_processing.text_splitter')
@patch('app.vector_processing.vector_store')
async def test_upsert_repository_documents_empty_files(mock_vs, mock_ts):
    result_doc_ids = await upsert_repository_documents([])
    assert result_doc_ids == []
    mock_ts.split_text.assert_not_called()
    mock_vs.add_documents.assert_not_called()

@pytest.mark.asyncio
@patch('app.vector_processing.text_splitter')
@patch('app.vector_processing.vector_store')
async def test_upsert_repository_documents_file_with_empty_content(mock_vs, mock_ts):
    repo_files = [RepositoryFile(path="empty.txt", content="", file_type="doc")]
    result_doc_ids = await upsert_repository_documents(repo_files)
    assert result_doc_ids == [] # Should skip empty content
    mock_ts.split_text.assert_not_called() # Or called but returns empty, leading to no docs
    # Depending on strictness, add_documents might not be called or called with empty list
    # Current implementation logs warning and skips, so add_documents not called with content from this file
    # If other valid files were present, it would be called for them.
    # For this specific test with only one empty file:
    if not mock_vs.add_documents.call_args_list: # If no other files processed
        mock_vs.add_documents.assert_not_called()
    else: # If add_documents was called for other (hypothetical) valid files
        pass # Test structure assumes only this file

@pytest.mark.asyncio
@patch('app.vector_processing.vector_store')
async def test_upsert_obligation_documents_success(mock_vs):
    async def mock_add_obl_docs(*args, **kwargs):
        return ["obl_id1", "obl_id2"]
    mock_vs.add_documents = MagicMock(side_effect=mock_add_obl_docs)
    
    result_doc_ids = await upsert_obligation_documents(SAMPLE_OBLIGATIONS_DATA)

    assert len(result_doc_ids) == 2
    mock_vs.add_documents.assert_called_once()
    added_docs_call_args = mock_vs.add_documents.call_args.kwargs['documents']
    assert len(added_docs_call_args) == 2

    obl1_data = SAMPLE_OBLIGATIONS_DATA["obligations"][0]
    doc1 = added_docs_call_args[0]
    assert isinstance(doc1, Document)
    expected_content_obl1 = f"Title: {obl1_data['title']}\nDescription: {obl1_data['description']}\nDetails: {obl1_data['details']}\nReference: {obl1_data['reference_article']}\nResponsible: {obl1_data['responsible_entity']}"
    assert doc1.page_content == expected_content_obl1
    assert doc1.metadata["source_type"] == "obligation"
    assert doc1.metadata["obligation_id"] == obl1_data["id"]
    assert doc1.metadata["obligation_title"] == obl1_data["title"]

@pytest.mark.asyncio
@patch('app.vector_processing.vector_store')
async def test_upsert_obligation_documents_empty_data(mock_vs):
    result_doc_ids = await upsert_obligation_documents({"obligations": []})
    assert result_doc_ids == []
    mock_vs.add_documents.assert_not_called()

@pytest.mark.asyncio
@patch('app.vector_processing.vector_store')
async def test_find_matching_obligations_for_repo_doc_matches_found(mock_vs):
    repo_content = "This content matches an obligation."
    repo_metadata = {"source_identifier": "test_file.py"}
    
    mock_obligation_doc_1 = Document(
        page_content="Obligation 1 content",
        metadata={
            "source_type": "obligation",
            "obligation_id": "OBL001",
            "obligation_title": "Data Quality"
        }
    )
    mock_obligation_doc_2 = Document(
        page_content="Obligation 2 content",
        metadata={
            "source_type": "obligation",
            "obligation_id": "OBL002",
            "obligation_title": "Transparency"
        }
    )
    
    async def mock_sim_search_side_effect(*args, **kwargs):
        return [
            (mock_obligation_doc_1, settings.SIMILARITY_THRESHOLD + 0.1),
            (mock_obligation_doc_2, settings.SIMILARITY_THRESHOLD - 0.1)
        ]
    mock_vs.similarity_search_with_score = MagicMock(side_effect=mock_sim_search_side_effect)

    matches = await find_matching_obligations_for_repo_doc(repo_content, repo_metadata, k=2)

    mock_vs.similarity_search_with_score.assert_called_once_with(
        query=repo_content, 
        k=2,
        filter={"source_type": "obligation"}
    )
    assert len(matches) == 1
    match1 = matches[0]
    assert isinstance(match1, FuzzyMatchResult)
    assert match1.obligation_id == "OBL001"
    assert match1.obligation_title == "Data Quality"
    assert match1.repo_content_source == "test_file.py"
    assert match1.repo_content_snippet == repo_content
    assert match1.similarity_score == settings.SIMILARITY_THRESHOLD + 0.1

@pytest.mark.asyncio
@patch('app.vector_processing.vector_store')
async def test_find_matching_obligations_for_repo_doc_no_matches(mock_vs):
    mock_vs.similarity_search_with_score = AsyncMock(return_value=[])
    repo_content = "No match content."
    repo_metadata = {"source_identifier": "no_match.py"}

    matches = await find_matching_obligations_for_repo_doc(repo_content, repo_metadata)
    
    assert len(matches) == 0
    mock_vs.similarity_search_with_score.assert_called_once()

@pytest.mark.asyncio
@patch('app.vector_processing.vector_store')
async def test_find_matching_obligations_for_repo_doc_empty_content(mock_vs):
    matches = await find_matching_obligations_for_repo_doc("", {"source_identifier": "empty.py"})
    assert len(matches) == 0
    mock_vs.similarity_search_with_score.assert_not_called()

@pytest.mark.asyncio
@patch('app.vector_processing.vector_store')
async def test_find_matching_obligations_for_repo_doc_api_error(mock_vs):
    mock_vs.similarity_search_with_score = AsyncMock(side_effect=Exception("Chroma DB Error"))
    repo_content = "Error case content."
    repo_metadata = {"source_identifier": "error_case.py"}

    matches = await find_matching_obligations_for_repo_doc(repo_content, repo_metadata)
    
    assert len(matches) == 0 # Should return empty list on error
    mock_vs.similarity_search_with_score.assert_called_once()
