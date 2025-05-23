from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import Engine
from contextlib import asynccontextmanager, contextmanager
from typing import Generator, AsyncGenerator

from app.config import settings

if not settings.DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in the environment variables or .env file.")

# Create SQLAlchemy engine
engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)

# Create sessionmaker
async_session_factory = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)

# Dependency for FastAPI
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides a database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

# Context manager for use in Celery tasks
@contextmanager
def get_db_context() -> Generator[AsyncSession, None, None]:
    """Context manager that provides a database session for synchronous code (like Celery tasks)."""
    session_context = async_session_factory()
    try:
        yield session_context
    except Exception:
        session_context.rollback()
        raise
    else:
        session_context.commit()
    finally:
        session_context.close()
