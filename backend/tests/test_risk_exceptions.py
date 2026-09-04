import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError
from backend.db.database import AsyncSessionLocal
from backend.governance.models import (
    RiskExceptionCreateRequest,
    RiskExceptionUpdateRequest,
    RiskExceptionApprovalRequest,
    RiskExceptionRenewalRequest,
    RiskExceptionActionRequest,
    RiskExceptionStatus,
    RiskExceptionSeverity,
    GovernanceDecision
)
from backend.governance.exceptions import (
    create_exception,
    update_exception,
    submit_for_approval,
    approve_exception,
    reject_exception,
    renew_exception,
    revoke_exception,
    close_exception,
    check_and_expire_exceptions,
    get_exception,
    list_exceptions,
    get_overdue_exceptions
)


def test_mandatory_future_expiration_validation():
    past_date = datetime.now(timezone.utc) - timedelta(days=1)
    with pytest.raises(ValidationError):
        RiskExceptionCreateRequest(
            title="Invalid Past Expiration Exception",
            description="Testing rejection of past expiration dates",
            severity=RiskExceptionSeverity.HIGH,
            business_justification="Temporary test justification requirement",
            owner="sec-ops",
            expires_at=past_date
        )


@pytest.mark.asyncio
async def test_risk_exception_lifecycle():
    async with AsyncSessionLocal() as session:
        future_exp = datetime.now(timezone.utc) + timedelta(days=30)
        req = RiskExceptionCreateRequest(
            title="DLP Redaction Test Exception",
            description="Accept temporary risk for internal benchmark pipeline",
            severity=RiskExceptionSeverity.HIGH,
            business_justification="Legitimate benchmark testing requiring unmasked tokens",
            compensating_controls="Strict tenant network isolation and VPC boundaries",
            owner="benchmark-team",
            expires_at=future_exp
        )

        # 1. Create (DRAFT)
        detail, event = await create_exception(session, req, actor="analyst-1")
        assert detail.status == RiskExceptionStatus.DRAFT.value
        assert detail.exception_id.startswith("EXC-")
        assert detail.risk_score == 60
        assert event.event_type == "SECURITY_RISK_EXCEPTION_CREATED"

        exc_id = detail.exception_id

        # 2. Update in DRAFT
        up_req = RiskExceptionUpdateRequest(title="Updated DLP Redaction Benchmark Exception")
        updated = await update_exception(session, exc_id, up_req, actor="analyst-1")
        assert updated.title == "Updated DLP Redaction Benchmark Exception"

        # 3. Submit for Approval
        submitted = await submit_for_approval(session, exc_id, actor="analyst-1")
        assert submitted.status == RiskExceptionStatus.PENDING_APPROVAL.value

        # 4. Approve
        app_req = RiskExceptionApprovalRequest(decision=GovernanceDecision.APPROVE, notes="Approved with quarterly review")
        approved = await approve_exception(session, exc_id, app_req, approver="security-admin")
        assert approved.status == RiskExceptionStatus.APPROVED.value
        assert approved.approved_by == "security-admin"
        assert approved.approved_at is not None

        # 5. Renew
        new_exp = datetime.now(timezone.utc) + timedelta(days=60)
        renew_req = RiskExceptionRenewalRequest(new_expires_at=new_exp, renewal_justification="Extended benchmark run")
        renewed = await renew_exception(session, exc_id, renew_req, actor="security-admin")
        assert renewed.status == RiskExceptionStatus.APPROVED.value
        assert renewed.expires_at == new_exp

        # 6. Revoke
        revoked = await revoke_exception(session, exc_id, reason="Benchmark concluded early", actor="security-admin")
        assert revoked.status == RiskExceptionStatus.REVOKED.value
        assert revoked.closed_at is not None


@pytest.mark.asyncio
async def test_rejection_and_invalid_transitions():
    async with AsyncSessionLocal() as session:
        future_exp = datetime.now(timezone.utc) + timedelta(days=14)
        req = RiskExceptionCreateRequest(
            title="Exception to be rejected",
            description="Testing formal governance rejection",
            severity=RiskExceptionSeverity.CRITICAL,
            business_justification="Testing rejection workflow",
            owner="app-team",
            expires_at=future_exp
        )

        detail, _ = await create_exception(session, req, actor="analyst-1")
        exc_id = detail.exception_id

        # Cannot approve directly from DRAFT without submission
        with pytest.raises(ValueError):
            await approve_exception(session, exc_id, RiskExceptionApprovalRequest(decision=GovernanceDecision.APPROVE))

        # Submit
        await submit_for_approval(session, exc_id, actor="analyst-1")

        # Reject
        rejected = await reject_exception(session, exc_id, RiskExceptionApprovalRequest(decision=GovernanceDecision.REJECT, notes="Inadequate compensating controls"))
        assert rejected.status == RiskExceptionStatus.REJECTED.value

        # Cannot update rejected exception
        with pytest.raises(ValueError):
            await update_exception(session, exc_id, RiskExceptionUpdateRequest(title="New title"))


@pytest.mark.asyncio
async def test_automatic_expiration_and_overdue():
    async with AsyncSessionLocal() as session:
        # Create an exception that is already due/expired
        future_exp = datetime.now(timezone.utc) + timedelta(seconds=1)
        req = RiskExceptionCreateRequest(
            title="Expiring Exception Test",
            description="Testing automatic expiration transition",
            severity=RiskExceptionSeverity.MEDIUM,
            business_justification="Testing expiration job",
            owner="qa-team",
            expires_at=future_exp
        )
        detail, _ = await create_exception(session, req, actor="analyst-1")
        exc_id = detail.exception_id
        await submit_for_approval(session, exc_id, actor="analyst-1")
        await approve_exception(session, exc_id, RiskExceptionApprovalRequest(decision=GovernanceDecision.APPROVE), approver="admin")

        # Simulate time passage
        simulated_now = datetime.now(timezone.utc) + timedelta(days=2)
        expired_count = await check_and_expire_exceptions(session, now=simulated_now)
        assert expired_count >= 1

        exp_detail = await get_exception(session, exc_id)
        assert exp_detail.status == RiskExceptionStatus.EXPIRED.value
