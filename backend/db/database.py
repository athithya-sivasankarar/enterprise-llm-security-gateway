import os
import re
import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import text
from dotenv import load_dotenv
from backend.db.models import Base

load_dotenv()

logger = logging.getLogger(__name__)

POSTGRES_USER = os.getenv("POSTGRES_USER", "gateway_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "gateway_password")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "security_gateway")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = (
        f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
        f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
    )

# Ensure postgresql+asyncpg driver prefix is used
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

SAFE_DATABASE_URL = re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", DATABASE_URL)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    poolclass=NullPool
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)


async def init_db() -> bool:
    """
    Initialize database schema (create tables and ensure columns exist).
    Fails safely with logging if database is unavailable.
    """
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            
            # Ensure response security, caching, provider, and policy_version columns exist
            await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS response_risk_score INTEGER DEFAULT 0"))
            await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS response_action VARCHAR(20)"))
            await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS response_threat_type VARCHAR(50)"))
            await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN DEFAULT FALSE"))
            await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS provider VARCHAR(50) DEFAULT 'mock'"))
            await conn.execute(text("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS policy_version VARCHAR(32) DEFAULT '1.0.0'"))
            await conn.execute(text("ALTER TABLE security_test_runs ALTER COLUMN status TYPE VARCHAR(50)"))
            await conn.execute(text("ALTER TABLE security_test_results ALTER COLUMN status TYPE VARCHAR(50)"))


        logger.info(f"Database schema initialized successfully ({SAFE_DATABASE_URL})")
        return True
    except Exception as e:
        logger.warning(f"Database initialization failed ({SAFE_DATABASE_URL}): {e}")
        return False


async def check_db_connection() -> bool:
    """
    Check if PostgreSQL database is reachable.
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for database session.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
