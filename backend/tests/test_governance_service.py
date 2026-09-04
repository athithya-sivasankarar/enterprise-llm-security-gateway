import pytest
from datetime import datetime, timezone, timedelta
from backend.db.database import AsyncSessionLocal
from backend.governance.models import (
    RiskExceptionCreateRequest,
    GovernanceReviewCreateRequest,
    GovernanceReviewType,
    RiskExceptionSeverity
)
from backend.services.governance_service import (
    get_governance_summary,
    get_governance_risk,
    create_risk_exception,
    run_control_assurance,
    create_governance_review,
    get_governance_events
)


@pytest.mark.asyncio
async def test_governance_service_full_workflow():
    async with AsyncSessionLocal() as session:
        # 1. Summary before
        sum_init = await get_governance_summary(session)
        assert sum_init.governance_risk_score >= 0
        assert sum_init.control_assurance_score >= 0

        # 2. Risk breakdown
        risk_breakdown = await get_governance_risk(session)
        assert risk_breakdown.overall_risk_score >= 0
        assert risk_breakdown.classification in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

        # 3. Create Exception
        exp_at = datetime.now(timezone.utc) + timedelta(days=30)
        req_exc = RiskExceptionCreateRequest(
            title="Service Layer Exception Test",
            description="Testing service orchestrator for risk exception creation",
            severity=RiskExceptionSeverity.MEDIUM,
            business_justification="Service layer unit validation test",
            owner="service-team",
            expires_at=exp_at
        )
        exc_detail = await create_risk_exception(session, req_exc, actor="service-tester")
        assert exc_detail.exception_id.startswith("EXC-")

        # 4. Run Assurance
        assurances = await run_control_assurance(session, actor="service-tester")
        assert len(assurances) == 14

        # 5. Create Review
        req_rev = GovernanceReviewCreateRequest(
            review_type=GovernanceReviewType.EXECUTIVE_SECURITY_REVIEW,
            scope="enterprise",
            reviewer="ciso",
            notes="Service test review"
        )
        rev = await create_governance_review(session, req_rev, reviewer="ciso")
        assert rev.review_id.startswith("REV-")

        # 6. Audit Events
        events = await get_governance_events(session, limit=20)
        assert len(events) >= 1
