import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.database import get_db
from backend.security.rbac import require_dashboard_access
from backend.governance.models import (
    RiskExceptionCreateRequest,
    RiskExceptionUpdateRequest,
    RiskExceptionApprovalRequest,
    RiskExceptionRenewalRequest,
    RiskExceptionActionRequest,
    RiskExceptionSummary,
    RiskExceptionDetail,
    ControlAssurance,
    GovernanceRiskBreakdown,
    GovernanceReviewCreateRequest,
    GovernanceReview,
    GovernanceSummary,
    GovernanceEvent
)
from backend.services.governance_service import (
    get_governance_summary as svc_get_summary,
    get_governance_risk as svc_get_risk,
    create_risk_exception as svc_create_exception,
    update_risk_exception as svc_update_exception,
    submit_exception as svc_submit_exception,
    approve_exception as svc_approve_exception,
    reject_exception as svc_reject_exception,
    renew_exception as svc_renew_exception,
    revoke_exception as svc_revoke_exception,
    close_exception as svc_close_exception,
    get_exceptions as svc_get_exceptions,
    get_exception_detail as svc_get_exception_detail,
    get_overdue_exceptions as svc_get_overdue_exceptions,
    run_control_assurance as svc_run_control_assurance,
    get_control_assurance as svc_get_control_assurance,
    create_governance_review as svc_create_governance_review,
    get_governance_review as svc_get_governance_review,
    list_governance_reviews as svc_list_governance_reviews,
    get_governance_events as svc_get_governance_events
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/governance", tags=["Security Governance, Risk Acceptance & Control Assurance"])


# =============================================================================
# 1. Summary & Risk Telemetry
# =============================================================================

@router.get("/summary", response_model=GovernanceSummary)
async def get_governance_summary(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get unified enterprise security governance summary posture.
    """
    return await svc_get_summary(db)


@router.get("/risk", response_model=GovernanceRiskBreakdown)
async def get_governance_risk(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get deterministic enterprise governance risk score and contributing risk factors.
    """
    return await svc_get_risk(db)


# =============================================================================
# 2. Control Assurance
# =============================================================================

@router.get("/controls", response_model=List[ControlAssurance])
@router.get("/assurance", response_model=List[ControlAssurance])
async def list_control_assurance(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List continuous control assurance records for all 14 security controls.
    """
    return await svc_get_control_assurance(db)


@router.get("/controls/{control_id}", response_model=List[ControlAssurance])
@router.get("/assurance/{control_id}", response_model=List[ControlAssurance])
async def get_control_assurance_by_id(
    control_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Get continuous control assurance assessment for a specific control.
    """
    res = await svc_get_control_assurance(db, control_id=control_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Control assurance for '{control_id}' not found"
        )
    return res


@router.post("/assurance/run", response_model=List[ControlAssurance])
async def run_control_assurance_evaluation(
    control_id: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Trigger manual continuous control assurance evaluation across security controls.
    """
    actor = user_data.get("user", "security-officer")
    return await svc_run_control_assurance(db, control_id=control_id, actor=actor)


# =============================================================================
# 3. Risk Exception Lifecycle Management
# =============================================================================

@router.post("/exceptions", response_model=RiskExceptionDetail, status_code=status.HTTP_201_CREATED)
async def create_risk_exception(
    req: RiskExceptionCreateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Create a governed risk exception.
    INVARIANT: Risk acceptance does NOT disable or weaken runtime security controls.
    """
    actor = user_data.get("user", "security-officer")
    try:
        return await svc_create_exception(db, req, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/exceptions/overdue", response_model=List[RiskExceptionSummary])
async def get_overdue_exceptions(
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve active risk exceptions that are past their review due date or expiration.
    """
    return await svc_get_overdue_exceptions(db)


@router.get("/exceptions", response_model=List[RiskExceptionSummary])
async def list_risk_exceptions(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    owner: Optional[str] = Query(default=None),
    asset_id: Optional[str] = Query(default=None),
    control_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List risk exceptions with optional status, severity, owner, asset, and control filtering.
    """
    return await svc_get_exceptions(
        db, status=status, severity=severity, owner=owner, asset_id=asset_id, control_id=control_id, limit=limit, offset=offset
    )


@router.get("/exceptions/{exception_id}", response_model=RiskExceptionDetail)
async def get_risk_exception(
    exception_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve complete detail for a specific risk exception.
    """
    exc = await svc_get_exception_detail(db, exception_id)
    if not exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Risk exception '{exception_id}' not found"
        )
    return exc


@router.put("/exceptions/{exception_id}", response_model=RiskExceptionDetail)
async def update_risk_exception(
    exception_id: str,
    req: RiskExceptionUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Update a DRAFT or PENDING_APPROVAL risk exception.
    """
    actor = user_data.get("user", "security-officer")
    try:
        return await svc_update_exception(db, exception_id, req, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/exceptions/{exception_id}/submit", response_model=RiskExceptionDetail)
async def submit_risk_exception_for_approval(
    exception_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Submit a DRAFT exception for formal executive approval.
    """
    actor = user_data.get("user", "security-officer")
    try:
        return await svc_submit_exception(db, exception_id, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/exceptions/{exception_id}/approve", response_model=RiskExceptionDetail)
async def approve_risk_exception(
    exception_id: str,
    req: RiskExceptionApprovalRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Approve a PENDING_APPROVAL risk exception (Admin and authorized security officers).
    """
    approver = user_data.get("user", "security-admin")
    try:
        return await svc_approve_exception(db, exception_id, req, approver=approver)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/exceptions/{exception_id}/reject", response_model=RiskExceptionDetail)
async def reject_risk_exception(
    exception_id: str,
    req: RiskExceptionApprovalRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Reject a PENDING_APPROVAL risk exception.
    """
    actor = user_data.get("user", "security-admin")
    try:
        return await svc_reject_exception(db, exception_id, req, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/exceptions/{exception_id}/renew", response_model=RiskExceptionDetail)
async def renew_risk_exception(
    exception_id: str,
    req: RiskExceptionRenewalRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Renew an APPROVED or EXPIRED risk exception with mandatory new future expiration date and justification.
    """
    actor = user_data.get("user", "security-admin")
    try:
        return await svc_renew_exception(db, exception_id, req, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/exceptions/{exception_id}/revoke", response_model=RiskExceptionDetail)
async def revoke_risk_exception(
    exception_id: str,
    req: Optional[RiskExceptionActionRequest] = None,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Revoke an active risk exception.
    """
    actor = user_data.get("user", "security-admin")
    reason = req.reason if req else None
    try:
        return await svc_revoke_exception(db, exception_id, reason=reason, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/exceptions/{exception_id}/close", response_model=RiskExceptionDetail)
async def close_risk_exception(
    exception_id: str,
    req: Optional[RiskExceptionActionRequest] = None,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Close a risk exception when remediation is completed.
    """
    actor = user_data.get("user", "security-admin")
    reason = req.reason if req else None
    try:
        return await svc_close_exception(db, exception_id, reason=reason, actor=actor)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# =============================================================================
# 4. Governance Reviews
# =============================================================================

@router.post("/reviews", response_model=GovernanceReview, status_code=status.HTTP_201_CREATED)
async def create_governance_review(
    req: GovernanceReviewCreateRequest,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Create and execute a periodic or ad-hoc security governance review.
    """
    reviewer = user_data.get("user", "security-officer")
    return await svc_create_governance_review(db, req, reviewer=reviewer)


@router.get("/reviews", response_model=List[GovernanceReview])
async def list_governance_reviews(
    review_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    List past completed and planned governance reviews.
    """
    return await svc_list_governance_reviews(db, review_type=review_type, status=status, limit=limit, offset=offset)


@router.get("/reviews/{review_id}", response_model=GovernanceReview)
async def get_governance_review(
    review_id: str,
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve specific governance review by ID.
    """
    review = await svc_get_governance_review(db, review_id)
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Governance review '{review_id}' not found"
        )
    return review


# =============================================================================
# 5. Governance Audit Events
# =============================================================================

@router.get("/events", response_model=List[GovernanceEvent])
async def list_governance_events(
    event_type: Optional[str] = Query(default=None),
    entity_type: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Retrieve immutable audit trail of security governance decisions and events.
    """
    return await svc_get_governance_events(db, event_type=event_type, entity_type=entity_type, limit=limit, offset=offset)
