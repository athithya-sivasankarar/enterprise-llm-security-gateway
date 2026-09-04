import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.db.database import AsyncSessionLocal
from backend.campaign.models import (
    CampaignCreateRequest,
    CampaignUpdateRequest,
    CampaignStatus
)
from backend.services.campaign_service import (
    create_campaign,
    get_campaign,
    list_campaigns,
    update_campaign,
    pause_campaign,
    resume_campaign,
    archive_campaign,
    set_baseline,
    execute_campaign,
    get_campaign_history,
    get_campaign_regressions
)


@pytest.mark.asyncio
async def test_campaign_crud_and_status_transitions():
    async with AsyncSessionLocal() as db_session:
        # 1. Create
        req = CampaignCreateRequest(
            name="Nightly Security Audit",
            description="Automated continuous adversarial testing",
            category_filter=["AUTHENTICATION", "PROMPT_INJECTION"],
            schedule_enabled=True,
            schedule_interval="daily"
        )
        camp = await create_campaign(db_session, req, user="admin-user")
        assert camp.name == "Nightly Security Audit"
        assert camp.status == "ACTIVE"
        assert camp.schedule_enabled is True
        assert "PROMPT_INJECTION" in camp.category_filter

        # 2. Get
        fetched = await get_campaign(db_session, camp.campaign_id)
        assert fetched.campaign_id == camp.campaign_id

        # 3. List
        all_camps = await list_campaigns(db_session)
        assert len(all_camps) >= 1

        # 4. Update
        up_req = CampaignUpdateRequest(description="Updated description")
        updated = await update_campaign(db_session, camp.campaign_id, up_req, user="admin-user")
        assert updated.description == "Updated description"

        # 5. Pause
        paused = await pause_campaign(db_session, camp.campaign_id, user="admin-user")
        assert paused.status == "PAUSED"

        # 6. Resume
        resumed = await resume_campaign(db_session, camp.campaign_id, user="admin-user")
        assert resumed.status == "ACTIVE"

        # 7. Archive
        archived = await archive_campaign(db_session, camp.campaign_id, user="admin-user")
        assert archived.status == "ARCHIVED"


@pytest.mark.asyncio
async def test_campaign_execution_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with AsyncSessionLocal() as db_session:
            # Create campaign
            req = CampaignCreateRequest(
                name="DLP & Auth Regression Campaign",
                category_filter=["AUTHENTICATION", "INPUT_DLP"]
            )
            camp = await create_campaign(db_session, req, user="admin-user")

            # Execute run with ASGI client
            run_summary, comparison = await execute_campaign(
                db_session,
                camp.campaign_id,
                user="admin-user",
                custom_client=client
            )

            assert run_summary.campaign_id == camp.campaign_id
            assert run_summary.status in ("COMPLETED", "COMPLETED_WITH_FAILURES", "COMPLETED_WITH_REGRESSIONS")
            assert run_summary.security_score > 0
            assert comparison.campaign_id == camp.campaign_id

            # History
            history = await get_campaign_history(db_session, camp.campaign_id)
            assert len(history) >= 1
            assert history[0].campaign_run_id == run_summary.campaign_run_id

            # Check updated campaign baseline
            updated_camp = await get_campaign(db_session, camp.campaign_id)
            assert updated_camp.last_run_id == run_summary.run_id
            assert updated_camp.baseline_run_id == run_summary.run_id


