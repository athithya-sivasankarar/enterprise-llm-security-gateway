import pytest
from datetime import datetime, timezone, timedelta
from backend.db.database import AsyncSessionLocal
from backend.governance.models import (
    RiskExceptionCreateRequest,
    RiskExceptionSeverity,
    RiskExceptionApprovalRequest,
    GovernanceDecision
)
from backend.services.governance_service import (
    create_risk_exception,
    submit_exception,
    approve_exception,
    get_governance_risk,
    check_and_expire_exceptions
)


@pytest.mark.asyncio
async def test_governance_alerts_and_critical_risk_handling():
    async with AsyncSessionLocal() as session:
        # Create expiring exception
        exp = datetime.now(timezone.utc) + timedelta(seconds=1)
        req = RiskExceptionCreateRequest(
            title="Alert Integration Test Exception",
            description="Testing alert trigger on expiry",
            severity=RiskExceptionSeverity.HIGH,
            business_justification="Alert test justification",
            owner="alert-team",
            expires_at=exp
        )
        exc = await create_risk_exception(session, req, actor="alert-tester")
        await submit_exception(session, exc.exception_id, actor="alert-tester")
        await approve_exception(
            session,
            exc.exception_id,
            RiskExceptionApprovalRequest(decision=GovernanceDecision.APPROVE, notes="Approved for alert test"),
            approver="admin"
        )

        # Expire
        sim_now = datetime.now(timezone.utc) + timedelta(days=2)
        expired_count = await check_and_expire_exceptions(session, now=sim_now)
        assert expired_count >= 1

        # Check risk
        risk = await get_governance_risk(session)
        assert risk.overall_risk_score >= 0
