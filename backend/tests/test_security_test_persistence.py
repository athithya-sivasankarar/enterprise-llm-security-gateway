import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from backend.main import app
from backend.db.database import AsyncSessionLocal
from backend.db.models import (
    SecurityTestRunModel,
    SecurityTestResultModel,
    SecurityTestFindingModel
)
from backend.redteam.runner import run_security_validation_suite


@pytest.mark.asyncio
async def test_security_test_persistence_database_records():
    """Verify that runs, results, and findings are stored in PostgreSQL with policy_version correlation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        report = await run_security_validation_suite(
            categories=["AUTHENTICATION", "INPUT_DLP"],
            created_by="persistence-tester",
            custom_client=client
        )
        run_id = report.run_id

        # Query database directly
        async with AsyncSessionLocal() as session:
            # 1. Verify Run record
            stmt_run = select(SecurityTestRunModel).where(SecurityTestRunModel.run_id == run_id)
            res_run = await session.execute(stmt_run)
            db_run = res_run.scalar_one_or_none()

            assert db_run is not None
            assert db_run.run_id == run_id
            assert db_run.created_by == "persistence-tester"
            assert db_run.policy_version is not None
            assert db_run.security_score == 100.0

            # 2. Verify Result records
            stmt_res = select(SecurityTestResultModel).where(SecurityTestResultModel.run_id == run_id)
            res_results = await session.execute(stmt_res)
            db_results = res_results.scalars().all()

            assert len(db_results) >= 7
            for r in db_results:
                assert r.run_id == run_id
                assert r.status == "PASS"
                assert r.category in ("AUTHENTICATION", "INPUT_DLP")
