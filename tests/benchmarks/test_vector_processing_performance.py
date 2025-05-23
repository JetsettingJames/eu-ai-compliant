"""
Performance benchmarks for the vector processing module.
"""
import pytest
import os
import asyncio
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, List

from langchain.schema import Document
from langchain_chroma import Chroma

from app.vector_processing import (
    upsert_repository_documents,
    upsert_obligation_documents,
    find_matching_obligations_for_repo_doc
)
from app.models import (
    RepositoryFile,
    FuzzyMatchResult
)
from app.config import settings

from tests.benchmarks.utils import benchmark, BenchmarkManager


@pytest.fixture
def mock_repository_files():
    """Create mock repository files for benchmarking."""
    return [
        RepositoryFile(
            path="README.md",
            content="""
            # Test Repository
            
            This is a test repository for benchmarking the vector processing module.
            
            ## Features
            
            - Feature 1: Description of feature 1
            - Feature 2: Description of feature 2
            
            ## Data Processing
            
            The system processes data using machine learning techniques.
            It ensures high quality of data through validation and preprocessing.
            
            ## Transparency
            
            The system provides transparency to users through detailed logs and explanations.
            """,
            file_type="doc"
        ),
        RepositoryFile(
            path="docs/api.md",
            content="""
            # API Documentation
            
            ## Endpoints
            
            ### GET /api/v1/data
            
            Get data from the API.
            
            ### POST /api/v1/model
            
            Train a model with the given data.
            
            ## Authentication
            
            API uses OAuth2 for authentication.
            """,
            file_type="doc"
        ),
        RepositoryFile(
            path="src/main.py",
            content="""
            import os
            import sys
            import numpy as np
            import pandas as pd
            
            def process_data(data_path):
                \"\"\"Process data from the given path.\"\"\"
                data = pd.read_csv(data_path)
                return data
            
            def main():
                \"\"\"Main function.\"\"\"
                data = process_data('data.csv')
                print(f"Data processed: {data.shape}")
            
            if __name__ == "__main__":
                main()
            """,
            file_type="code"
        )
    ]


@pytest.fixture
def mock_obligations_data():
    """Mock obligations data for benchmarking."""
    return {
        "obligations": [
            {
                "id": "OBL001",
                "title": "Data Quality",
                "description": "Ensure high quality of data.",
                "details": "Detailed explanation of data quality requirements.",
                "tier_category": "high_general",
                "reference_article": "Art. 10",
                "responsible_entity": "Entity 1",
                "keywords": ["data", "quality", "validation", "preprocessing"]
            },
            {
                "id": "OBL002",
                "title": "Transparency",
                "description": "Provide transparency to users.",
                "details": "Detailed explanation of transparency requirements.",
                "tier_category": "high_general",
                "reference_article": "Art. 13",
                "responsible_entity": "Entity 2",
                "keywords": ["transparency", "explanation", "interpretability"]
            },
            {
                "id": "OBL003",
                "title": "Human Oversight",
                "description": "Ensure human oversight of AI systems.",
                "details": "Detailed explanation of human oversight requirements.",
                "tier_category": "high_general",
                "reference_article": "Art. 14",
                "responsible_entity": "Entity 3",
                "keywords": ["human", "oversight", "intervention", "control"]
            }
        ]
    }


@pytest.fixture
def mock_embedded_content():
    """Mock embedded content for benchmarking find_matching_obligations_for_repo_doc.
    Returns a tuple of (repo_doc_content_str, repo_doc_metadata_dict).
    """
    repo_doc_content_str = "This is a sample repository document about data quality and transparency."
    repo_doc_metadata_dict = {
        "source_identifier": "sample/repo/doc.md",
        "source_type": "repository_file",
        "file_type": "doc"
    }
    return repo_doc_content_str, repo_doc_metadata_dict


@pytest.fixture
def mock_vector_store():
    """Mock vector store for benchmarking."""
    mock = MagicMock(spec=Chroma)
    mock.add_documents = AsyncMock(return_value=["doc_id_1", "doc_id_2"])
    mock.similarity_search_with_score = AsyncMock(return_value=[
        (Document(page_content="High quality of data is essential.", metadata={"id": "obl_1", "obligation_id": "OBL001", "obligation_title": "Data Quality"}), 0.85),
        (Document(page_content="Transparency is important for user trust.", metadata={"id": "obl_2", "obligation_id": "OBL002", "obligation_title": "Transparency"}), 0.78)
    ])
    return mock


@pytest.mark.asyncio
@benchmark(iterations=3, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for upsert_repository_documents function"})
async def test_upsert_repository_documents_performance(mock_repository_files, mock_vector_store):
    """Benchmark the upsert_repository_documents function."""
    with patch('app.vector_processing.vector_store', new=mock_vector_store):
        # Mock the behavior of add_texts or add_documents if necessary
        # For example, if upsert_repository_documents calls vector_store.add_documents:
        mock_vector_store.add_documents = AsyncMock(return_value=["doc_id_1", "doc_id_2"])
        
        result_ids = await upsert_repository_documents(repo_files=mock_repository_files)
        assert result_ids is not None
        assert len(result_ids) > 0
        mock_vector_store.add_documents.assert_called()
    return result_ids


@pytest.mark.asyncio
@benchmark(iterations=3, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for upsert_obligation_documents function"})
async def test_upsert_obligation_documents_performance(mock_obligations_data, mock_vector_store):
    """Benchmark the upsert_obligation_documents function."""
    with patch('app.vector_processing.vector_store', new=mock_vector_store):
        # Mock the behavior of add_texts or add_documents
        mock_vector_store.add_documents = AsyncMock(return_value=["obl_id_1", "obl_id_2"])
        
        result_ids = await upsert_obligation_documents(obligations_data=mock_obligations_data)
        assert result_ids is not None
        assert len(result_ids) > 0
        mock_vector_store.add_documents.assert_called()
    return result_ids


@pytest.mark.asyncio
@benchmark(iterations=3, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for find_matching_obligations_for_repo_doc function"})
async def test_find_matching_obligations_performance(mock_embedded_content, mock_vector_store):
    """Benchmark the find_matching_obligations_for_repo_doc function."""
    repo_doc_content, repo_doc_metadata = mock_embedded_content
    # The mock_vector_store fixture is already set up to mock the vector_store used by find_matching_obligations_for_repo_doc
    # No need to patch get_vector_store here if find_matching_obligations_for_repo_doc directly uses an imported vector_store instance.
    # However, the function app.vector_processing.find_matching_obligations_for_repo_doc uses `vector_store.similarity_search_with_score`
    # and `vector_store` is a global variable in that module, initialized with Chroma(...).
    # So, we need to patch that global `vector_store` instance.
    with patch('app.vector_processing.vector_store', new=mock_vector_store):
        result = await find_matching_obligations_for_repo_doc(
            repo_doc_content=repo_doc_content,
            repo_doc_metadata=repo_doc_metadata
        )
        assert result is not None
        return result
