from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os
from typing import Optional, Any
import logging

# Load .env file at the earliest opportunity
load_dotenv()

# Basic logger for config loading issues or info
config_logger = logging.getLogger(__name__ + ".config")
config_logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
if not config_logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    config_logger.addHandler(handler)


class Settings(BaseSettings):
    # API Keys and Service Endpoints
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GITHUB_TOKEN: Optional[str] = os.getenv("GITHUB_TOKEN")

    # LLM Configuration
    OPENAI_MODEL_NAME: str = os.getenv("OPENAI_MODEL_NAME", "gpt-4o")
    EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "text-embedding-ada-002")
    RISK_CLASSIFICATION_MODEL: str = os.getenv("RISK_CLASSIFICATION_MODEL", "gpt-4o")
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.3"))
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "1500"))

    # ChromaDB Configuration
    CHROMA_PERSIST_PATH: str = os.getenv("CHROMA_PERSIST_PATH", "./chroma_db_store")
    CHROMA_COLLECTION_NAME: str = os.getenv("CHROMA_COLLECTION_NAME", "eu_ai_compliance_collection")

    # Repository Processing Configuration
    MAX_REPO_SIZE_MB: int = int(os.getenv("MAX_REPO_SIZE_MB", "50"))
    DOWNLOAD_TIMEOUT_SECONDS: int = int(os.getenv("DOWNLOAD_TIMEOUT_SECONDS", "60"))

    # Database Configuration
    DATABASE_URL: Optional[str] = os.getenv("DATABASE_URL")

    # Redis Configuration
    REDIS_URL: Optional[str] = os.getenv("REDIS_URL")
    CACHE_TTL: int = int(os.getenv("CACHE_TTL", "3600"))  # Default cache TTL in seconds (1 hour)

    # Application settings
    APP_NAME: str = "EU AI Act Compliance Assistant - RepoScanner"
    API_V1_STR: str = "/api/v1"
    SENTRY_DSN: str | None = os.getenv("SENTRY_DSN")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()


    class Config:
        # If you have a .env file, it will be loaded automatically by pydantic-settings
        # but we are explicitly calling load_dotenv() above for clarity and to ensure it runs early.
        pass

settings = Settings()

# If DATABASE_URL is not set by environment, default to a local SQLite file DB for dev
if settings.DATABASE_URL is None:
    default_db_url = "sqlite+aiosqlite:///./eu_ai_compliant_dev.db"
    config_logger.info(f"DATABASE_URL not found in environment, defaulting to local SQLite DB: {default_db_url}")
    settings.DATABASE_URL = default_db_url