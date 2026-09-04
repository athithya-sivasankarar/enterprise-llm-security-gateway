import pytest
from datetime import datetime, timezone, timedelta
from backend.db.database import AsyncSessionLocal
from backend.governance.models import (
    RiskExceptionCreateRequest,
    RiskExceptionSeverity,
    RiskExceptionApprovalRequest,
    GovernanceReviewCreateRequest,
    GovernanceReviewType,
    GovernanceDecision
)
from backend.reporting.models import ReportCreateRequest, ReportType
from backend.services.governance_service import (
    create_risk_exception,
    submit_exception,
    approve_exception,
    run_control_assurance,
    get_governance_risk,
    get_governance_summary,
    create_governance_review
)
from backend.services.report_service import create_report, get_report



@pytest.mark.asyncio
async def test_full_governance_e2e_scenario():
    """
    End-to-end synthetic validation:
    Security Test Validation / Gap -> Exposure & Incident Correlation ->
    Risk Exception Lifecycle -> Continuous Control Assurance ->
    Governance Review -> Executive Governance Report Generation.
    """
    async with AsyncSessionLocal() as session:
        # 1. Initial State & Control Assurance Evaluation
        assurances = await run_control_assurance(session, actor="e2e-runner")
        assert len(assurances) == 14

        # 2. Risk Exception Request
        future_exp = datetime.now(timezone.utc) + timedelta(days=60)
        req_exc = RiskExceptionCreateRequest(
            title="E2E Synthetic Risk Acceptance",
            description="Governed risk exception for multi-domain validation scenario",
            risk_type="PROMPT_INJECTION",
            severity=RiskExceptionSeverity.HIGH,
            business_justification="Temporary exception for red-team testing suite execution",
            compensating_controls="Strict audit logging, rate limiting, and ephemeral test tenants",
            owner="redteam-lead",
            expires_at=future_exp
        )
        exc_detail = await create_risk_exception(session, req_exc, actor="redteam-lead")
        assert exc_detail.status == "DRAFT"

        # 3. Exception Approval Lifecycle
        await submit_exception(session, exc_detail.exception_id, actor="redteam-lead")
        app_res = await approve_exception(
            session,
            exc_detail.exception_id,
            RiskExceptionApprovalRequest(decision=GovernanceDecision.APPROVE, notes="Approved for benchmark"),
            approver="security-admin"
        )
        assert app_res.status == "APPROVED"

        # 4. Governance Risk Scoring & Posture Summary
        gov_risk = await get_governance_risk(session)
        assert gov_risk.overall_risk_score >= 0
        assert gov_risk.classification in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

        gov_sum = await get_governance_summary(session)
        assert gov_sum.total_controls == 14
        assert gov_sum.open_exceptions >= 1

        # 5. Governance Review Execution
        req_rev = GovernanceReviewCreateRequest(
            review_type=GovernanceReviewType.EXECUTIVE_SECURITY_REVIEW,
            scope="enterprise-wide",
            reviewer="chief-risk-officer",
            notes="End-to-end synthetic governance validation review"
        )
        rev = await create_governance_review(session, req_rev, reviewer="chief-risk-officer")
        assert rev.review_id.startswith("REV-")
        assert rev.overall_score >= 0.0

        # 6. Governance Report Generation
        req_rep = ReportCreateRequest(
            report_type=ReportType.GOVERNANCE.value,
            title="End-to-End Synthetic Governance Report",
            description="Complete executive governance assurance and risk acceptance summary."
        )
        rep_sum = await create_report(session, req_rep, user="chief-risk-officer")
        assert rep_sum.report_id.startswith("rep-")

        rep_detail = await get_report(session, rep_sum.report_id)
        assert rep_detail.executive_summary is not None
        assert rep_detail.report_hash is not None
