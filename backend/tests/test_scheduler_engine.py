import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.db.database import AsyncSessionLocal
from backend.campaign.models import CampaignCreateRequest
from backend.scheduler.models import ScheduleCreateRequest
from backend.services.campaign_service import create_campaign, pause_campaign
from backend.services.scheduler_service import create_schedule, get_schedule
from backend.scheduler.engine import get_due_schedules, execute_scheduled_campaign
from backend.services.scheduler_lock import acquire_campaign_lock, release_campaign_lock


@pytest.mark.asyncio
async def test_due_schedules_detection():
    async with AsyncSessionLocal() as session:
        # Create campaign and schedule with next_run in the past
        camp_req = CampaignCreateRequest(
            name="Due Schedule Test Campaign",
            category_filter=["AUTHENTICATION"]
        )
        camp = await create_campaign(session, camp_req, user="admin-user")

        sched_req = ScheduleCreateRequest(
            schedule_type="INTERVAL",
            interval_minutes=60,
            enabled=True
        )
        sched = await create_schedule(session, camp.campaign_id, sched_req, user="admin-user")

        # Check due schedules with future check time
        future = datetime.now(timezone.utc) + timedelta(days=2)
        due = await get_due_schedules(session, as_of=future)
        sched_ids = [s.schedule_id for s in due]
        assert sched.schedule_id in sched_ids


@pytest.mark.asyncio
async def test_scheduler_engine_execution_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with AsyncSessionLocal() as session:
            camp_req = CampaignCreateRequest(
                name="Engine Execution Test Campaign",
                category_filter=["AUTHENTICATION", "INPUT_DLP"]
            )
            camp = await create_campaign(session, camp_req, user="admin-user")

            sched_req = ScheduleCreateRequest(
                schedule_type="INTERVAL",
                interval_minutes=60,
                enabled=True
            )
            sched = await create_schedule(session, camp.campaign_id, sched_req, user="admin-user")

            # Execute scheduled run
            success, err = await execute_scheduled_campaign(sched.schedule_id, custom_client=client)
            assert success is True
            assert err is None

            # Verify updated schedule state
            updated = await get_schedule(session, camp.campaign_id)
            assert updated.last_run_at is not None
            assert updated.last_run_status in ("COMPLETED", "COMPLETED_WITH_REGRESSIONS")
            assert updated.next_run_at is not None
            assert updated.last_error is None


@pytest.mark.asyncio
async def test_paused_campaign_skipped_by_scheduler():
    async with AsyncSessionLocal() as session:
        camp_req = CampaignCreateRequest(
            name="Paused Campaign Schedule Test",
            category_filter=["AUTHENTICATION"]
        )
        camp = await create_campaign(session, camp_req, user="admin-user")

        sched_req = ScheduleCreateRequest(
            schedule_type="INTERVAL",
            interval_minutes=60,
            enabled=True
        )
        sched = await create_schedule(session, camp.campaign_id, sched_req, user="admin-user")

        # Pause the campaign
        await pause_campaign(session, camp.campaign_id, user="admin-user")

        # Execute scheduled run
        success, msg = await execute_scheduled_campaign(sched.schedule_id)
        assert success is False
        assert "PAUSED" in msg


@pytest.mark.asyncio
async def test_distributed_locking_prevents_duplicate_execution():
    async with AsyncSessionLocal() as session:
        camp_req = CampaignCreateRequest(
            name="Locking Test Campaign",
            category_filter=["AUTHENTICATION"]
        )
        camp = await create_campaign(session, camp_req, user="admin-user")

        # Pre-acquire the lock
        acquired = await acquire_campaign_lock(camp.campaign_id, ttl_seconds=60)
        assert acquired is True

        # Attempt to acquire lock again -> must fail
        second_attempt = await acquire_campaign_lock(camp.campaign_id, ttl_seconds=60)
        assert second_attempt is False

        # Release lock
        await release_campaign_lock(camp.campaign_id)

        # Now acquisition succeeds
        reacquired = await acquire_campaign_lock(camp.campaign_id, ttl_seconds=60)
        assert reacquired is True
        await release_campaign_lock(camp.campaign_id)
