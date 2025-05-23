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
    find_matching_obligations_for_repo_doc,
    find_fuzzy_matches
)
from app.models import (
    RepositoryFile,
    FuzzyMatchResult,
    EmbeddedContentItem
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
    """Mock embedded content for benchmarking."""
    return [
        EmbeddedContentItem(
            id="doc_1",
            content="This is a test repository for benchmarking the vector processing module.",
            metadata={
                "source": "README.md",
                "type": "doc"
            }
        ),
        EmbeddedContentItem(
            id="doc_2",
            content="The system processes data using machine learning techniques.",
            metadata={
                "source": "README.md",
                "type": "doc"
            }
        ),
        EmbeddedContentItem(
            id="doc_3",
            content="It ensures high quality of data through validation and preprocessing.",
            metadata={
                "source": "README.md",
                "type": "doc"
            }
        ),
        EmbeddedContentItem(
            id="doc_4",
            content="The system provides transparency to users through detailed logs and explanations.",
            metadata={
                "source": "README.md",
                "type": "doc"
            }
        )
    ]


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
    with patch('app.vector_processing.get_vector_store', return_value=mock_vector_store):
        with patch('app.vector_processing.text_splitter') as mock_splitter:
            # Configure the text splitter to return simple chunks
            mock_splitter.split_text.side_effect = lambda text: [text[:100], text[100:200]] if len(text) > 100 else [text]
            
            result = await upsert_repository_documents(mock_repository_files)
            assert result is not None
            return result


@pytest.mark.asyncio
@benchmark(iterations=3, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for upsert_obligation_documents function"})
async def test_upsert_obligation_documents_performance(mock_obligations_data, mock_vector_store):
    """Benchmark the upsert_obligation_documents function."""
    with patch('app.vector_processing.get_vector_store', return_value=mock_vector_store):
        with patch('app.vector_processing.text_splitter') as mock_splitter:
            # Configure the text splitter to return simple chunks
            mock_splitter.split_text.side_effect = lambda text: [text[:100], text[100:200]] if len(text) > 100 else [text]
            
            result = await upsert_obligation_documents(mock_obligations_data)
            assert result is not None
            return result


@pytest.mark.asyncio
@benchmark(iterations=3, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for find_matching_obligations_for_repo_doc function"})
async def test_find_matching_obligations_performance(mock_embedded_content, mock_vector_store):
    """Benchmark the find_matching_obligations_for_repo_doc function."""
    with patch('app.vector_processing.get_vector_store', return_value=mock_vector_store):
        result = await find_matching_obligations_for_repo_doc(mock_embedded_content)
        assert result is not None
        return result


@benchmark(iterations=5, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for find_fuzzy_matches function"})
def test_find_fuzzy_matches_performance():
    """Benchmark the find_fuzzy_matches function."""
    # Create sample data for testing
    repo_content = [
        "This is a test repository for benchmarking.",
        "The system processes data using machine learning techniques.",
        "It ensures high quality of data through validation and preprocessing.",
        "The system provides transparency to users through detailed logs and explanations."
    ]
    
    obligation_content = [
        "Data Quality: Ensure high quality of data through validation.",
        "Transparency: Provide transparency to users through explanations.",
        "Human Oversight: Ensure human oversight of AI systems."
    ]
    
    # Mock similarity scores
    similarity_scores = [
        [0.85, 0.45, 0.30],  # Scores for repo_content[0]
        [0.60, 0.50, 0.40],  # Scores for repo_content[1]
        [0.90, 0.40, 0.35],  # Scores for repo_content[2]
        [0.55, 0.88, 0.42]   # Scores for repo_content[3]
    ]
    
    # Create mock embeddings function
    def mock_get_embedding(text):
        # Return a simple mock embedding
        return [0.1] * 10
    
    # Create mock similarity function
    def mock_calculate_similarity(embed1, embed2):
        # Find the index of the texts to return the pre-defined similarity score
        repo_idx = -1
        for i, text in enumerate(repo_content):
            if text in embed1 or text in embed2:
                repo_idx = i
                break
        
        obl_idx = -1
        for i, text in enumerate(obligation_content):
            if text in embed1 or text in embed2:
                obl_idx = i
                break
        
        if repo_idx >= 0 and obl_idx >= 0:
            return similarity_scores[repo_idx][obl_idx]
        return 0.5  # Default similarity
    
    with patch('app.vector_processing.calculate_cosine_similarity', side_effect=mock_calculate_similarity):
        with patch('app.vector_processing.get_embedding', side_effect=mock_get_embedding):
            result = find_fuzzy_matches(
                repo_content=repo_content,
                obligation_content=obligation_content,
                similarity_threshold=0.75
            )
            
            assert result is not None
            assert len(result) > 0
            return result


def generate_performance_report():
    """Generate a performance report from benchmark results."""
    # Run benchmarks
    asyncio.run(test_upsert_repository_documents_performance(mock_repository_files(), mock_vector_store()))
    asyncio.run(test_upsert_obligation_documents_performance(mock_obligations_data(), mock_vector_store()))
    asyncio.run(test_find_matching_obligations_performance(mock_embedded_content(), mock_vector_store()))
    test_find_fuzzy_matches_performance()
    
    # Load results
    benchmark_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'benchmark_results')
    result_files = [os.path.join(benchmark_dir, f) for f in os.listdir(benchmark_dir) if f.endswith('.json')]
    
    results = [BenchmarkManager.load_result(f) for f in result_files]
    
    # Generate report
    report_path = BenchmarkManager.generate_report(results)
    print(f"Performance report generated at: {report_path}")
    
    return report_path


if __name__ == "__main__":
    generate_performance_report()
