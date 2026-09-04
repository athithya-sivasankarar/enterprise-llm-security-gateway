import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityExposureModel
from backend.governance.models import (
    RiskExceptionCreateRequest,
    RiskExceptionSeverity,
    RiskExceptionApprovalRequest,
    GovernanceDecision
)
from backend.services.governance_service import (
    create_risk_exception,
    submit_exception,
    approve_exception
)


@pytest.mark.asyncio
async def test_exposure_integration_no_auto_resolve():
    async with AsyncSessionLocal() as session:
        now = datetime.now(timezone.utc)
        uid = uuid.uuid4().hex[:8].upper()
        exp_id = f"EXP-GOV-{uid}"

        # 1. Create Open Exposure
        exp_model = SecurityExposureModel(
            exposure_id=exp_id,
            asset_id="ast-llm-api",
            category="SECRET_LEAKAGE",
            severity="CRITICAL",
            risk_score=75,
            exposure_type="CONTROL_GAP",
            description="Testing exposure and risk exception tracking",
            status="OPEN",
            first_detected_at=now,
            last_detected_at=now
        )
        session.add(exp_model)
        await session.commit()

        # 2. Create Risk Exception for Exposure
        exp_date = now + timedelta(days=30)
        req = RiskExceptionCreateRequest(
            title=f"Accepted Risk for Exposure {exp_id}",
            description="Accept risk temporarily for secret leakage in staging",
            severity=RiskExceptionSeverity.CRITICAL,
            exposure_id=exp_id,
            asset_id="ast-llm-api",
            business_justification="Accepting risk during Q1 test migration",
            owner="infra-team",
            expires_at=exp_date
        )
        detail = await create_risk_exception(session, req, actor="sec-lead")
        await submit_exception(session, detail.exception_id, actor="sec-lead")
        await approve_exception(
            session,
            detail.exception_id,
            RiskExceptionApprovalRequest(decision=GovernanceDecision.APPROVE),
            approver="admin"
        )

        # 3. CRITICAL INVARIANT: Verify exposure remains OPEN
        res_exp = await session.execute(select(SecurityExposureModel).where(SecurityExposureModel.exposure_id == exp_id))
        verified_exp = res_exp.scalar_one()
        assert verified_exp.status == "OPEN", "Exposure must remain OPEN even when risk exception is APPROVED"
