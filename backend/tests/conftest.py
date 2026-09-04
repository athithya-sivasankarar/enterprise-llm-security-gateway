import pytest_asyncio
from backend.db.database import init_db, AsyncSessionLocal
from backend.services.policy_service import init_default_policy_if_empty


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_database():
    """
    Ensure database schema, columns, and default security policy are initialized
    before any automated tests execute.
    """
    await init_db()
    async with AsyncSessionLocal() as session:
        await init_default_policy_if_empty(session)
    yield
