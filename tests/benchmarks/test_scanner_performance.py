"""
Performance benchmarks for the scanner module.
"""
import pytest
import os
import asyncio
import tempfile
import shutil
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, List

from app.scanner import (
    scan_repo,
    determine_risk_tier,
    find_documentation_files,
    extract_text_and_headings_from_markdown,
    analyze_python_code_ast
)
from app.models import (
    RepoInputModel,
    RepoInfo,
    CodeSignal,
    GrepSignalItem
)
from app.config import settings

from tests.benchmarks.utils import benchmark, BenchmarkManager


@pytest.fixture
def mock_repo_path():
    """Create a temporary directory with mock repository files."""
    temp_dir = tempfile.mkdtemp()
    
    # Create mock files
    os.makedirs(os.path.join(temp_dir, "src"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "docs"), exist_ok=True)
    
    # Create README.md
    with open(os.path.join(temp_dir, "README.md"), "w") as f:
        f.write("""
        # Test Repository
        
        This is a test repository for benchmarking the scanner module.
        
        ## Features
        
        - Feature 1: Description of feature 1
        - Feature 2: Description of feature 2
        
        ## Usage
        
        ```python
        import example
        
        example.run()
        ```
        
        ## License
        
        MIT
        """)
    
    # Create Python files
    with open(os.path.join(temp_dir, "src", "main.py"), "w") as f:
        f.write("""
        import os
        import sys
        import numpy as np
        import pandas as pd
        from sklearn.model_selection import train_test_split
        
        def process_data(data_path):
            \"\"\"Process data from the given path.\"\"\"
            data = pd.read_csv(data_path)
            return data
        
        def train_model(data):
            \"\"\"Train a machine learning model.\"\"\"
            X = data.drop('target', axis=1)
            y = data['target']
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
            
            # Train model
            model = np.random.rand(X_train.shape[1])
            return model
        
        def main():
            \"\"\"Main function.\"\"\"
            data = process_data('data.csv')
            model = train_model(data)
            print(f"Model trained: {model}")
        
        if __name__ == "__main__":
            main()
        """)
    
    # Create documentation files
    with open(os.path.join(temp_dir, "docs", "api.md"), "w") as f:
        f.write("""
        # API Documentation
        
        ## Endpoints
        
        ### GET /api/v1/data
        
        Get data from the API.
        
        ### POST /api/v1/model
        
        Train a model with the given data.
        
        ## Authentication
        
        API uses OAuth2 for authentication.
        """)
    
    yield temp_dir
    
    # Cleanup
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_obligations_data():
    """Mock obligations data for benchmarking."""
    return {
        "prohibited": {
            "overall_tier_keywords": ["biometric", "social scoring", "manipulation"],
            "obligations": [
                {
                    "id": "P001",
                    "title": "Prohibited Practice 1",
                    "description": "Description of prohibited practice 1",
                    "reference": "Art. 5(1)(a)",
                    "type": "general",
                    "keywords": ["biometric", "identification", "public", "spaces"]
                }
            ]
        },
        "high": {
            "overall_tier_keywords": ["critical", "infrastructure", "medical", "law enforcement"],
            "obligations": [
                {
                    "id": "H001",
                    "title": "High Risk Obligation 1",
                    "description": "Description of high risk obligation 1",
                    "reference": "Art. 10",
                    "type": "general",
                    "keywords": ["data", "quality", "training", "validation"]
                }
            ]
        },
        "limited": {
            "overall_tier_keywords": ["emotion", "recognition", "biometric", "categorization"],
            "obligations": [
                {
                    "id": "L001",
                    "title": "Limited Risk Obligation 1",
                    "description": "Description of limited risk obligation 1",
                    "reference": "Art. 52",
                    "type": "general",
                    "keywords": ["transparency", "disclosure", "human", "interaction"]
                }
            ]
        },
        "minimal": {
            "overall_tier_keywords": ["general", "purpose", "chatbot", "non-critical"],
            "obligations": [
                {
                    "id": "M001",
                    "title": "Minimal Risk Obligation 1",
                    "description": "Description of minimal risk obligation 1",
                    "reference": "Art. 69",
                    "type": "general",
                    "keywords": ["voluntary", "code", "practice", "standards"]
                }
            ]
        }
    }


@benchmark(iterations=5, warmup=1, track_memory=True, 
          metadata={"description": "Benchmark for find_documentation_files function"})
def test_find_documentation_files_performance(mock_repo_path):
    """Benchmark the find_documentation_files function."""
    result = find_documentation_files(mock_repo_path)
    assert result is not None
    assert "markdown" in result
    assert "openapi" in result
    return result


@benchmark(iterations=5, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for extract_text_and_headings_from_markdown function"})
def test_extract_markdown_performance(mock_repo_path):
    """Benchmark the extract_text_and_headings_from_markdown function."""
    readme_path = os.path.join(mock_repo_path, "README.md")
    with open(readme_path, "r") as f:
        content = f.read()
    
    text, headings = extract_text_and_headings_from_markdown(content)
    assert text is not None
    assert headings is not None
    return text, headings


@benchmark(iterations=5, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for analyze_python_code_ast function"})
def test_analyze_python_code_performance(mock_repo_path):
    """Benchmark the analyze_python_code_ast function."""
    python_file = os.path.join(mock_repo_path, "src", "main.py")
    with open(python_file, "r") as f:
        content = f.read()
    
    result = analyze_python_code_ast(python_file, content)
    assert result is not None
    return result


@pytest.mark.asyncio
@benchmark(iterations=3, warmup=1, track_memory=True,
          metadata={"description": "Benchmark for determine_risk_tier function"})
async def test_determine_risk_tier_performance(mock_obligations_data):
    """Benchmark the determine_risk_tier function."""
    doc_summary_bullets = [
        "This is a machine learning system for data processing.",
        "It uses pandas and numpy for data manipulation.",
        "The system is designed for general-purpose data analysis.",
        "It includes a simple model training functionality.",
        "Documentation includes API endpoints and authentication details."
    ]
    
    code_signals = CodeSignal(
        uses_biometric=False,
        uses_facial_recognition=False,
        uses_emotion_recognition=False,
        uses_categorization=False,
        uses_image_generation=False,
        uses_real_time_video=False,
        uses_nlp=True,
        uses_gpt=False,
        uses_llm=False,
        uses_deep_learning=True,
        uses_tensorflow=False,
        uses_pytorch=False,
        uses_scikit_learn=True
    )
    
    grep_signals = [
        GrepSignalItem(
            file_path="src/main.py",
            line_number=5,
            line_content="from sklearn.model_selection import train_test_split",
            signal_type="machine_learning"
        )
    ]
    
    tier, analysis_details = await determine_risk_tier(
        doc_summary_bullets,
        code_signals,
        grep_signals,
        mock_obligations_data
    )
    
    assert tier is not None
    assert analysis_details is not None
    return tier, analysis_details


@pytest.mark.asyncio
async def test_scan_repo_performance():
    """
    Benchmark the scan_repo function with mocked dependencies.
    
    This test doesn't use the @benchmark decorator directly because
    it requires complex mocking. Instead, we manually measure performance.
    """
    # This test requires extensive mocking of dependencies
    # and is more suitable for a separate integration test
    # that can be run in a controlled environment.
    pass


def generate_performance_report():
    """Generate a performance report from benchmark results."""
    # Run benchmarks
    test_find_documentation_files_performance(mock_repo_path())
    test_extract_markdown_performance(mock_repo_path())
    test_analyze_python_code_performance(mock_repo_path())
    
    # Run async benchmarks
    asyncio.run(test_determine_risk_tier_performance(mock_obligations_data()))
    
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
