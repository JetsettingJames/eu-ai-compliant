# EU AI Act Compliance Assistant - RepoScanner Service

A comprehensive solution for scanning GitHub repositories to assess compliance with the European Union's Artificial Intelligence Act (EU AI Act). This service analyzes code, documentation, and repository structure to determine the applicable risk tier and provide detailed compliance guidance.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running the Application](#running-the-application)
  - [Running with Docker](#running-with-docker-optional)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)
- [Compliance Configuration](#compliance-configuration)
- [Performance Testing](#performance-testing)
  - [Benchmarking Framework](#benchmarking-framework)
  - [Running Benchmarks](#running-benchmarks)
  - [Optimization Recommendations](#optimization-recommendations)
- [Contributing](#contributing)
- [License](#license)

## Overview

The EU AI Act Compliance Assistant is designed to help developers and organizations understand how the EU AI Act applies to their AI systems. By analyzing a GitHub repository, the service determines the appropriate risk tier (prohibited, high, limited, or minimal) and provides a detailed checklist of compliance obligations.

## System Architecture

The system follows a modular architecture with the following components:

1. **FastAPI Web Service**: Provides REST API endpoints for scanning repositories and retrieving results.
2. **Scanning Engine**: Core logic for repository analysis and compliance assessment.
3. **Vector Database**: ChromaDB for semantic search and fuzzy matching of compliance obligations.
4. **Relational Database**: PostgreSQL for storing scan results and historical data.
5. **Caching Layer**: Redis for performance optimization and caching frequently accessed data.
6. **LLM Integration**: OpenAI API for advanced text analysis and summarization.
7. **Compliance Configuration**: YAML-based configuration for risk tiers, obligations, and compliance requirements.
8. **LangGraph Orchestration**: Manages the scanning workflow as a directed graph of operations.

## Key Features

1. **Repository Analysis Pipeline**:
   - **Fetches & Unzips**: Downloads a GitHub repository and extracts its contents.
   - **Documentation Extraction**: Parses README.md, docs/**/*.md, and OpenAPI/Swagger files.
   - **LLM-Powered Summarization**: Uses OpenAI to generate a summary of the system's purpose, data, and users.
   - **Code Analysis**: Examines code for use of specific libraries or APIs (e.g., biometrics, real-time streams).
   - **AST-Based Scanning**: Uses Abstract Syntax Trees to analyze Python code structure.
   - **Grep-Style Keyword Search**: Identifies potential compliance issues through pattern matching.

2. **Advanced Compliance Assessment**:
   - **Multi-Tier Risk Classification**: Determines risk tier (prohibited, high, limited, minimal) based on multiple signals.
   - **Confidence Scoring**: Assigns confidence levels to each compliance finding.
   - **Evidence Collection**: Gathers and organizes evidence supporting the risk classification.
   - **Detailed Analysis**: Provides comprehensive breakdown of compliance matches across all risk tiers.

3. **Vector-Based Fuzzy Matching**:
   - **Semantic Search**: Uses embeddings to find relevant compliance obligations.
   - **ChromaDB Integration**: Local vector database for efficient similarity search.
   - **Contextual Matching**: Identifies compliance requirements based on code and documentation context.

4. **Persistence and History**:
   - **Scan History**: Maintains a record of previous scans for tracking compliance over time.
   - **Database Integration**: Stores results in PostgreSQL for long-term retention.
   - **Caching**: Uses Redis to improve performance for frequently accessed data.

5. **Asynchronous Processing**:
   - **Non-Blocking API**: Handles long-running scans without blocking the API.
   - **Celery Integration**: Background task processing for improved scalability.
   - **Task Status Tracking**: Monitors and reports on scan progress.

## Tech Stack

- **Language**: Python 3.10+
- **Framework**: FastAPI
- **Database**: PostgreSQL (via SQLAlchemy)
- **Vector Store**: ChromaDB
- **Cache**: Redis
- **Task Queue**: Celery
- **LLM**: OpenAI API (GPT-4o)
- **Embeddings**: OpenAI Embeddings API
- **Workflow**: LangGraph
- **Key Libraries**: 
  - `langchain` - For LLM workflows and embeddings
  - `langchain-chroma` - For vector database integration
  - `httpx` - For async HTTP requests
  - `PyYAML` - For configuration parsing
  - `SQLAlchemy` - For database ORM
  - `pydantic` - For data validation
  - `alembic` - For database migrations
  - `zipfile` - For repository extraction
  - `ast` - For Python code analysis

## Getting Started

### Prerequisites

- Python 3.10+
- Access to an OpenAI API key
- PostgreSQL database (optional, falls back to SQLite)
- Redis (optional, for caching)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/eu-ai-compliant.git
cd eu-ai-compliant

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows use `.\venv\Scripts\activate`

# 3. Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the root directory with the following variables:

```
# Required
OPENAI_API_KEY="your_openai_api_key"

# Optional (defaults will be used if not provided)
EMBEDDING_MODEL="text-embedding-ada-002"  # OpenAI embedding model
GITHUB_TOKEN="your_github_pat_optional_for_public_repos"
DATABASE_URL="postgresql+asyncpg://user:password@host:port/dbname"  # Falls back to SQLite
REDIS_URL="redis://localhost:6379/0"  # Optional, for caching
CHROMA_PERSIST_PATH="./chroma_db_store"  # Path for ChromaDB storage
CHROMA_COLLECTION_NAME="my_compliance_vectors"  # Name for ChromaDB collection
```

### Running the Application

```bash
# Start the web server
uvicorn app.main:app --reload

# In a separate terminal, start Celery worker (optional, for async processing)
celery -A app.worker worker --loglevel=info

# In another terminal, start Flower for monitoring Celery tasks (optional)
celery -A app.worker flower --port=5555
```

The API will be available at `http://127.0.0.1:8000`.
The API documentation will be available at `http://127.0.0.1:8000/docs`.
Celery Flower monitoring will be available at `http://127.0.0.1:5555`.

### Running with Docker (Optional)

```bash
# Build and start the containers
docker-compose up -d

# The API will be available at http://localhost:8000
# The API documentation will be available at http://localhost:8000/docs
# Celery Flower monitoring will be available at http://localhost:5555
```

## API Endpoints

### Core Endpoints

- `POST /api/v1/scan`: Triggers a new synchronous repository scan.
  - **Request Body**: See `app/models.py` for `RepoInputModel`.
  - **Response Body**: See `app/models.py` for `ScanResultModel`.

### Asynchronous Endpoints

- `POST /api/v1/scan-async`: Triggers an asynchronous repository scan.
  - **Request Body**: Same as `/scan`.
  - **Response Body**: Task ID for checking status.

- `GET /api/v1/scan-status/{task_id}`: Check the status of an asynchronous scan.
  - **Response Body**: Task status and result if complete.

### History and Records

- `GET /api/v1/scan-records`: Lists all scan records with pagination and filtering.
- `GET /api/v1/scan-history`: Retrieves scan history for a specific repository.
- `GET /api/v1/scan-records/{scan_id}`: Retrieves a specific scan record by ID.

### Utility Endpoints

- `GET /`: Basic welcome message and API status.
- `GET /health`: Health check endpoint.

## Project Structure

```
eu-ai-compliant/
├── app/                    # Main application code
│   ├── api/                # API endpoints
│   ├── config.py           # Application configuration
│   ├── crud/               # Database CRUD operations
│   ├── db/                 # Database models and session management
│   ├── graph_nodes.py      # LangGraph nodes for scanning workflow
│   ├── graph_orchestrator.py # LangGraph workflow orchestration
│   ├── logger.py           # Logging configuration
│   ├── main.py             # FastAPI application entry point
│   ├── models.py           # Pydantic models for API requests/responses
│   ├── scanner.py          # Core scanning logic
│   ├── services/           # External service integrations
│   ├── utils/              # Utility functions
│   │   ├── compliance.py   # Compliance utilities
│   │   ├── repo_utils.py   # Repository utilities
│   │   └── yaml_config.py  # YAML configuration loader
│   ├── vector_processing.py # Vector database operations
│   └── worker.py           # Celery worker configuration
├── data/                   # YAML configuration files
│   ├── compliance_config.yaml # General compliance configuration
│   ├── obligations.yaml    # Detailed compliance obligations
│   └── risk_tiers.yaml     # Risk tier definitions
├── tests/                  # Unit and integration tests
├── .env.example           # Example environment variables
├── docker-compose.yml      # Docker Compose configuration
├── Dockerfile              # Docker build configuration
├── requirements.txt        # Python dependencies
└── README.md              # Project documentation
```

## Compliance Configuration

The system uses YAML files to configure compliance rules and requirements. These files are located in the `data/` directory:

### 1. `risk_tiers.yaml`

Defines the risk tiers according to the EU AI Act, including descriptions and criteria for each tier.

### 2. `compliance_config.yaml`

Contains general compliance configuration, including:
- Assessment settings
- Signal libraries and keywords
- Documentation requirements
- Regulatory deadlines

### 3. `obligations.yaml`

Details the specific compliance obligations for each risk tier, organized by category. Each obligation includes:
- ID and title
- Keywords for detection
- Reference to the relevant EU AI Act article
- Deadline for compliance

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and adhere to the existing coding style.

## Performance Testing

The EU AI Compliance Assistant includes a comprehensive benchmarking framework to measure, analyze, and improve performance across critical components of the system.

### Benchmarking Framework

The benchmarking framework provides tools for measuring execution time, memory usage, and system resource utilization. Key features include:

- **Detailed Metrics**: Captures execution time (min, max, average, median), memory usage, and standard deviation.
- **Visualization**: Generates performance plots for visual analysis of benchmark results.
- **Comprehensive Reports**: Creates HTML and CSV reports with detailed performance data.
- **Optimization Recommendations**: Automatically generates suggestions for performance improvements.

### Running Benchmarks

```bash
# Run all benchmarks
python -m tests.benchmarks.run_benchmarks

# Run specific benchmark modules
python -m tests.benchmarks.run_benchmarks --modules test_scanner_performance.py test_vector_processing_performance.py

# Generate report from existing results without running benchmarks
python -m tests.benchmarks.run_benchmarks --report-only
```

Benchmark results are stored in the `benchmark_results` directory, including JSON data files, performance plots, and HTML reports.

### Optimization Recommendations

The benchmarking framework automatically analyzes performance data and generates optimization recommendations. These recommendations target:

1. **Slowest Operations**: Identifies the most time-consuming functions and suggests specific optimizations.
2. **Memory Usage**: Highlights memory-intensive operations and provides strategies to reduce memory footprint.
3. **General Improvements**: Offers general recommendations for caching, parallel processing, and I/O optimization.

To implement these optimizations:

1. Review the generated recommendations in `benchmark_results/consolidated_report_*/optimization_recommendations.txt`.
2. Prioritize optimizations based on impact and implementation complexity.
3. Implement changes incrementally, running benchmarks after each change to measure improvement.
4. Focus on critical paths first, especially those in the scanner and vector processing modules.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
