import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityIncidentModel
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
async def test_incident_integration_no_auto_resolve():
    async with AsyncSessionLocal() as session:
        now = datetime.now(timezone.utc)
        uid = uuid.uuid4().hex[:8].upper()
        inc_id = f"INC-GOV-{uid}"

        # 1. Create Open Incident
        inc = SecurityIncidentModel(
            incident_id=inc_id,
            title="Open Incident Under Investigation",
            description="Testing incident risk exception correlation",
            incident_type="PROMPT_INJECTION",
            severity="HIGH",
            status="OPEN",
            created_at=now,
            updated_at=now
        )
        session.add(inc)
        await session.commit()

        # 2. Create and Approve Risk Exception linking to incident
        exp = now + timedelta(days=30)
        req = RiskExceptionCreateRequest(
            title=f"Risk Exception for Incident {inc_id}",
            description="Documenting accepted business risk while patch is developed",
            severity=RiskExceptionSeverity.HIGH,
            incident_id=inc_id,
            business_justification="Temporary risk acceptance pending architectural redesign",
            compensating_controls="Enhanced audit logging and rate limiting",
            owner="incident-response-team",
            expires_at=exp
        )
        detail = await create_risk_exception(session, req, actor="incident-analyst")
        await submit_exception(session, detail.exception_id, actor="incident-analyst")
        await approve_exception(
            session,
            detail.exception_id,
            RiskExceptionApprovalRequest(decision=GovernanceDecision.APPROVE, notes="Approved risk exception"),
            approver="security-admin"
        )

        # 3. CRITICAL INVARIANT: Verify incident status is STILL OPEN (not automatically resolved)
        res_inc = await session.execute(select(SecurityIncidentModel).where(SecurityIncidentModel.incident_id == inc_id))
        verified_inc = res_inc.scalar_one()
        assert verified_inc.status == "OPEN", "Incident must remain OPEN even after risk exception approval"
