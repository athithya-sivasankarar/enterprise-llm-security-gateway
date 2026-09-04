import pytest
from datetime import datetime, timezone
from sqlalchemy import select

from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityScheduleModel, SecurityAlertModel
from backend.campaign.models import CampaignCreateRequest
from backend.scheduler.models import ScheduleCreateRequest
from backend.services.campaign_service import create_campaign
from backend.services.scheduler_service import create_schedule, disable_schedule, enable_schedule
from backend.services.alert_service import acknowledge_alert, resolve_alert
from backend.alerts.engine import record_execution_error_alert


@pytest.mark.asyncio
async def test_scheduler_persistence_database_records():
    async with AsyncSessionLocal() as session:
        # Create campaign
        camp_req = CampaignCreateRequest(
            name="Persistence Test Campaign",
            category_filter=["AUTHENTICATION"]
        )
        camp = await create_campaign(session, camp_req, user="persistence-tester")

        # Create schedule
        sched_req = ScheduleCreateRequest(
            schedule_type="CRON",
            cron_expression="0 */6 * * *",
            enabled=True
        )
        sched = await create_schedule(session, camp.campaign_id, sched_req, user="persistence-tester")

        # Query database for schedule
        stmt = select(SecurityScheduleModel).where(SecurityScheduleModel.schedule_id == sched.schedule_id)
        res = await session.execute(stmt)
        db_sched = res.scalar_one_or_none()

        assert db_sched is not None
        assert db_sched.campaign_id == camp.campaign_id
        assert db_sched.cron_expression == "0 */6 * * *"
        assert db_sched.enabled is True
        assert db_sched.next_run_at is not None

        # Create alert
        alert = await record_execution_error_alert(
            session, camp.campaign_id, "Persistence test execution failure"
        )

        # Query database for alert
        stmt_alert = select(SecurityAlertModel).where(SecurityAlertModel.alert_id == alert.alert_id)
        res_alert = await session.execute(stmt_alert)
        db_alert = res_alert.scalar_one_or_none()

        assert db_alert is not None
        assert db_alert.campaign_id == camp.campaign_id
        assert db_alert.status == "OPEN"

        # Acknowledge and resolve alert
        await acknowledge_alert(session, alert.alert_id, user="analyst-user")
        await resolve_alert(session, alert.alert_id, user="admin-user")

        # Query updated alert
        res_up_alert = await session.execute(stmt_alert)
        up_alert = res_up_alert.scalar_one_or_none()
        assert up_alert.status == "RESOLVED"
        assert up_alert.resolved_by == "admin-user"
        assert up_alert.acknowledged_by == "analyst-user"
