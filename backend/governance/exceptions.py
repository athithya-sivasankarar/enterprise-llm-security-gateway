import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, or_, and_, desc

from backend.db.models import SecurityRiskExceptionModel, SecurityGovernanceEventModel
from backend.governance.models import (
    RiskExceptionStatus,
    RiskExceptionSeverity,
    RiskExceptionCreateRequest,
    RiskExceptionUpdateRequest,
    RiskExceptionApprovalRequest,
    RiskExceptionRenewalRequest,
    RiskExceptionDetail,
    RiskExceptionSummary,
    GovernanceDecision
)
from backend.governance.sanitizer import sanitize_governance_text, sanitize_governance_metadata

logger = logging.getLogger(__name__)

SEVERITY_DEFAULT_SCORES = {
    RiskExceptionSeverity.CRITICAL: 80,
    RiskExceptionSeverity.HIGH: 60,
    RiskExceptionSeverity.MEDIUM: 40,
    RiskExceptionSeverity.LOW: 20,
    "CRITICAL": 80,
    "HIGH": 60,
    "MEDIUM": 40,
    "LOW": 20,
}


def _is_expired(model: SecurityRiskExceptionModel, now: datetime) -> bool:
    if model.expires_at:
        exp = model.expires_at if model.expires_at.tzinfo else model.expires_at.replace(tzinfo=timezone.utc)
        return exp <= now
    return False


def _is_overdue(model: SecurityRiskExceptionModel, now: datetime) -> bool:
    if model.status in (RiskExceptionStatus.APPROVED.value, RiskExceptionStatus.PENDING_APPROVAL.value):
        if model.review_due_at:
            rev = model.review_due_at if model.review_due_at.tzinfo else model.review_due_at.replace(tzinfo=timezone.utc)
            if rev <= now:
                return True
        return _is_expired(model, now)
    return False


def _to_detail(model: SecurityRiskExceptionModel, now: Optional[datetime] = None) -> RiskExceptionDetail:
    if now is None:
        now = datetime.now(timezone.utc)
    return RiskExceptionDetail(
        id=model.id,
        exception_id=model.exception_id,
        title=model.title,
        description=model.description,
        risk_type=model.risk_type,
        severity=model.severity,
        status=model.status,
        asset_id=model.asset_id,
        control_id=model.control_id,
        exposure_id=model.exposure_id,
        incident_id=model.incident_id,
        source_type=model.source_type,
        source_id=model.source_id,
        business_justification=model.business_justification,
        compensating_controls=model.compensating_controls,
        owner=model.owner,
        requested_by=model.requested_by,
        approved_by=model.approved_by,
        requested_at=model.requested_at,
        approved_at=model.approved_at,
        effective_from=model.effective_from,
        expires_at=model.expires_at,
        review_due_at=model.review_due_at,
        risk_score=model.risk_score,
        policy_version=model.policy_version or "1.0.0",
        created_at=model.created_at,
        updated_at=model.updated_at,
        closed_at=model.closed_at,
        is_expired=_is_expired(model, now),
        is_overdue=_is_overdue(model, now)
    )


def _to_summary(model: SecurityRiskExceptionModel, now: Optional[datetime] = None) -> RiskExceptionSummary:
    if now is None:
        now = datetime.now(timezone.utc)
    return RiskExceptionSummary(
        id=model.id,
        exception_id=model.exception_id,
        title=model.title,
        severity=model.severity,
        status=model.status,
        owner=model.owner,
        asset_id=model.asset_id,
        control_id=model.control_id,
        exposure_id=model.exposure_id,
        incident_id=model.incident_id,
        risk_score=model.risk_score,
        requested_by=model.requested_by,
        approved_by=model.approved_by,
        effective_from=model.effective_from,
        expires_at=model.expires_at,
        review_due_at=model.review_due_at,
        is_expired=_is_expired(model, now),
        is_overdue=_is_overdue(model, now),
        created_at=model.created_at
    )


async def create_exception(
    db: AsyncSession,
    req: RiskExceptionCreateRequest,
    actor: str = "system"
) -> Tuple[RiskExceptionDetail, SecurityGovernanceEventModel]:
    now = datetime.now(timezone.utc)
    exc_uuid = uuid.uuid4().hex[:8].upper()
    exception_id = f"EXC-{exc_uuid}"

    # Calculate default risk score if absent
    risk_score = req.risk_score
    if risk_score is None:
        risk_score = SEVERITY_DEFAULT_SCORES.get(req.severity, 50)
    risk_score = max(0, min(100, risk_score))

    # Sanitize inputs
    sanitized_title = sanitize_governance_text(req.title)
    sanitized_desc = sanitize_governance_text(req.description)
    sanitized_justification = sanitize_governance_text(req.business_justification)
    sanitized_comp = sanitize_governance_text(req.compensating_controls) if req.compensating_controls else None

    # Guarantee timezone awareness
    exp_at = req.expires_at if req.expires_at.tzinfo else req.expires_at.replace(tzinfo=timezone.utc)
    rev_due = None
    if req.review_due_at:
        rev_due = req.review_due_at if req.review_due_at.tzinfo else req.review_due_at.replace(tzinfo=timezone.utc)

    model = SecurityRiskExceptionModel(
        exception_id=exception_id,
        title=sanitized_title,
        description=sanitized_desc,
        risk_type=req.risk_type,
        severity=req.severity.value if hasattr(req.severity, "value") else str(req.severity),
        status=RiskExceptionStatus.DRAFT.value,
        asset_id=req.asset_id,
        control_id=req.control_id,
        exposure_id=req.exposure_id,
        incident_id=req.incident_id,
        source_type=req.source_type,
        source_id=req.source_id,
        business_justification=sanitized_justification,
        compensating_controls=sanitized_comp,
        owner=req.owner,
        requested_by=actor,
        approved_by=None,
        requested_at=now,
        approved_at=None,
        effective_from=now,
        expires_at=exp_at,
        review_due_at=rev_due,
        risk_score=risk_score,
        policy_version="1.0.0",
        created_at=now,
        updated_at=now
    )

    db.add(model)

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_RISK_EXCEPTION_CREATED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Created risk exception '{sanitized_title}' for owner {req.owner}",
        metadata_json=sanitize_governance_metadata({
            "exception_id": exception_id,
            "severity": model.severity,
            "owner": model.owner,
            "risk_score": risk_score,
            "expires_at": exp_at.isoformat()
        }),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_detail(model, now), event


async def update_exception(
    db: AsyncSession,
    exception_id: str,
    req: RiskExceptionUpdateRequest,
    actor: str = "system"
) -> RiskExceptionDetail:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exception_id))
    model = res.scalar_one_or_none()
    if not model:
        raise ValueError(f"Risk exception '{exception_id}' not found")

    if model.status not in (RiskExceptionStatus.DRAFT.value, RiskExceptionStatus.PENDING_APPROVAL.value):
        raise ValueError(f"Cannot update risk exception in '{model.status}' status. Only DRAFT or PENDING_APPROVAL exceptions can be edited.")

    if req.title:
        model.title = sanitize_governance_text(req.title)
    if req.description:
        model.description = sanitize_governance_text(req.description)
    if req.risk_type:
        model.risk_type = req.risk_type
    if req.severity:
        model.severity = req.severity.value if hasattr(req.severity, "value") else str(req.severity)
        model.risk_score = SEVERITY_DEFAULT_SCORES.get(model.severity, model.risk_score)
    if req.business_justification:
        model.business_justification = sanitize_governance_text(req.business_justification)
    if req.compensating_controls is not None:
        model.compensating_controls = sanitize_governance_text(req.compensating_controls)
    if req.owner:
        model.owner = req.owner
    if req.expires_at:
        exp = req.expires_at if req.expires_at.tzinfo else req.expires_at.replace(tzinfo=timezone.utc)
        model.expires_at = exp
    if req.review_due_at:
        rev = req.review_due_at if req.review_due_at.tzinfo else req.review_due_at.replace(tzinfo=timezone.utc)
        model.review_due_at = rev

    model.updated_at = now

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_RISK_EXCEPTION_UPDATED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Updated risk exception '{exception_id}' details",
        metadata_json=sanitize_governance_metadata({"exception_id": exception_id}),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_detail(model, now)


async def submit_for_approval(
    db: AsyncSession,
    exception_id: str,
    actor: str = "system"
) -> RiskExceptionDetail:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exception_id))
    model = res.scalar_one_or_none()
    if not model:
        raise ValueError(f"Risk exception '{exception_id}' not found")

    if model.status != RiskExceptionStatus.DRAFT.value:
        raise ValueError(f"Only DRAFT exceptions can be submitted for approval (current status: '{model.status}')")

    model.status = RiskExceptionStatus.PENDING_APPROVAL.value
    model.updated_at = now

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_RISK_EXCEPTION_SUBMITTED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Submitted risk exception '{exception_id}' for executive approval",
        metadata_json=sanitize_governance_metadata({"exception_id": exception_id, "status": model.status}),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_detail(model, now)


async def approve_exception(
    db: AsyncSession,
    exception_id: str,
    req: RiskExceptionApprovalRequest,
    approver: str = "security-admin"
) -> RiskExceptionDetail:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exception_id))
    model = res.scalar_one_or_none()
    if not model:
        raise ValueError(f"Risk exception '{exception_id}' not found")

    if model.status != RiskExceptionStatus.PENDING_APPROVAL.value:
        raise ValueError(f"Cannot approve exception in '{model.status}' status. Exception must be PENDING_APPROVAL.")

    # Validate not expired
    exp = model.expires_at if model.expires_at.tzinfo else model.expires_at.replace(tzinfo=timezone.utc)
    if exp <= now:
        raise ValueError(f"Cannot approve exception: expiration date {exp.isoformat()} has already elapsed")

    actual_approver = req.approved_by or approver
    model.status = RiskExceptionStatus.APPROVED.value
    model.approved_by = actual_approver
    model.approved_at = now
    model.updated_at = now

    if req.notes:
        sanitized_notes = sanitize_governance_text(req.notes)
        model.business_justification = f"{model.business_justification}\n[Approval Note by {actual_approver}]: {sanitized_notes}"

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_RISK_EXCEPTION_APPROVED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actual_approver,
        description=f"Approved risk exception '{exception_id}' by {actual_approver}",
        metadata_json=sanitize_governance_metadata({
            "exception_id": exception_id,
            "approved_by": actual_approver,
            "expires_at": exp.isoformat()
        }),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_detail(model, now)


async def reject_exception(
    db: AsyncSession,
    exception_id: str,
    req: RiskExceptionApprovalRequest,
    actor: str = "security-admin"
) -> RiskExceptionDetail:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exception_id))
    model = res.scalar_one_or_none()
    if not model:
        raise ValueError(f"Risk exception '{exception_id}' not found")

    if model.status != RiskExceptionStatus.PENDING_APPROVAL.value:
        raise ValueError(f"Cannot reject exception in '{model.status}' status. Exception must be PENDING_APPROVAL.")

    actual_actor = req.approved_by or actor
    model.status = RiskExceptionStatus.REJECTED.value
    model.closed_at = now
    model.updated_at = now

    if req.notes:
        sanitized_notes = sanitize_governance_text(req.notes)
        model.business_justification = f"{model.business_justification}\n[Rejection Note by {actual_actor}]: {sanitized_notes}"

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_RISK_EXCEPTION_REJECTED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actual_actor,
        description=f"Rejected risk exception '{exception_id}' by {actual_actor}",
        metadata_json=sanitize_governance_metadata({"exception_id": exception_id, "rejected_by": actual_actor}),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_detail(model, now)


async def renew_exception(
    db: AsyncSession,
    exception_id: str,
    req: RiskExceptionRenewalRequest,
    actor: str = "security-admin"
) -> RiskExceptionDetail:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exception_id))
    model = res.scalar_one_or_none()
    if not model:
        raise ValueError(f"Risk exception '{exception_id}' not found")

    if model.status not in (RiskExceptionStatus.APPROVED.value, RiskExceptionStatus.EXPIRED.value):
        raise ValueError(f"Cannot renew exception in '{model.status}' status. Only APPROVED or EXPIRED exceptions can be renewed.")

    new_exp = req.new_expires_at if req.new_expires_at.tzinfo else req.new_expires_at.replace(tzinfo=timezone.utc)
    if new_exp <= now:
        raise ValueError("Renewal expiration date must be strictly in the future")

    sanitized_justification = sanitize_governance_text(req.renewal_justification)
    reviewer = req.reviewer or actor

    model.expires_at = new_exp
    model.status = RiskExceptionStatus.APPROVED.value
    model.approved_by = reviewer
    model.approved_at = now
    model.closed_at = None
    model.business_justification = f"{model.business_justification}\n[Renewal Justification by {reviewer} on {now.isoformat()}]: {sanitized_justification}"
    model.updated_at = now

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_RISK_EXCEPTION_RENEWED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=reviewer,
        description=f"Renewed risk exception '{exception_id}' until {new_exp.isoformat()} by {reviewer}",
        metadata_json=sanitize_governance_metadata({
            "exception_id": exception_id,
            "new_expires_at": new_exp.isoformat(),
            "renewed_by": reviewer
        }),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_detail(model, now)


async def revoke_exception(
    db: AsyncSession,
    exception_id: str,
    reason: Optional[str] = None,
    actor: str = "security-admin"
) -> RiskExceptionDetail:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exception_id))
    model = res.scalar_one_or_none()
    if not model:
        raise ValueError(f"Risk exception '{exception_id}' not found")

    if model.status in (RiskExceptionStatus.REVOKED.value, RiskExceptionStatus.CLOSED.value):
        raise ValueError(f"Risk exception '{exception_id}' is already {model.status}")

    model.status = RiskExceptionStatus.REVOKED.value
    model.closed_at = now
    model.updated_at = now

    if reason:
        sanitized_reason = sanitize_governance_text(reason)
        model.business_justification = f"{model.business_justification}\n[Revocation Reason by {actor}]: {sanitized_reason}"

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_RISK_EXCEPTION_REVOKED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Revoked risk exception '{exception_id}' by {actor}",
        metadata_json=sanitize_governance_metadata({"exception_id": exception_id, "revoked_by": actor}),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_detail(model, now)


async def close_exception(
    db: AsyncSession,
    exception_id: str,
    reason: Optional[str] = None,
    actor: str = "security-admin"
) -> RiskExceptionDetail:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exception_id))
    model = res.scalar_one_or_none()
    if not model:
        raise ValueError(f"Risk exception '{exception_id}' not found")

    model.status = RiskExceptionStatus.CLOSED.value
    model.closed_at = now
    model.updated_at = now

    if reason:
        sanitized_reason = sanitize_governance_text(reason)
        model.business_justification = f"{model.business_justification}\n[Closure Reason by {actor}]: {sanitized_reason}"

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_RISK_EXCEPTION_CLOSED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Closed risk exception '{exception_id}' by {actor}",
        metadata_json=sanitize_governance_metadata({"exception_id": exception_id, "closed_by": actor}),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_detail(model, now)


async def check_and_expire_exceptions(
    db: AsyncSession,
    now: Optional[datetime] = None
) -> int:
    """
    Find active exceptions that have passed their expiration date and transition them to EXPIRED.
    Emits an audit governance event for each expired exception.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    stmt = select(SecurityRiskExceptionModel).where(
        and_(
            SecurityRiskExceptionModel.status.in_([RiskExceptionStatus.APPROVED.value, RiskExceptionStatus.PENDING_APPROVAL.value]),
            SecurityRiskExceptionModel.expires_at <= now
        )
    )
    res = await db.execute(stmt)
    expired_models = res.scalars().all()
    count = 0

    for model in expired_models:
        model.status = RiskExceptionStatus.EXPIRED.value
        model.updated_at = now
        event = SecurityGovernanceEventModel(
            event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
            event_type="SECURITY_RISK_EXCEPTION_EXPIRED",
            entity_type="EXCEPTION",
            entity_id=model.exception_id,
            actor="system",
            description=f"Risk exception '{model.exception_id}' expired at {model.expires_at.isoformat()}",
            metadata_json=sanitize_governance_metadata({
                "exception_id": model.exception_id,
                "expires_at": model.expires_at.isoformat()
            }),
            created_at=now
        )
        db.add(event)
        count += 1

    if count > 0:
        await db.commit()
        logger.info(f"Transitioned {count} risk exception(s) to EXPIRED status")

    return count


async def get_exception(
    db: AsyncSession,
    exception_id: str
) -> Optional[RiskExceptionDetail]:
    now = datetime.now(timezone.utc)
    res = await db.execute(select(SecurityRiskExceptionModel).where(SecurityRiskExceptionModel.exception_id == exception_id))
    model = res.scalar_one_or_none()
    if not model:
        return None
    return _to_detail(model, now)


async def list_exceptions(
    db: AsyncSession,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    owner: Optional[str] = None,
    asset_id: Optional[str] = None,
    control_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[RiskExceptionSummary]:
    now = datetime.now(timezone.utc)
    query = select(SecurityRiskExceptionModel)

    if status:
        query = query.where(SecurityRiskExceptionModel.status == status.upper())
    if severity:
        query = query.where(SecurityRiskExceptionModel.severity == severity.upper())
    if owner:
        query = query.where(SecurityRiskExceptionModel.owner == owner)
    if asset_id:
        query = query.where(SecurityRiskExceptionModel.asset_id == asset_id)
    if control_id:
        query = query.where(SecurityRiskExceptionModel.control_id == control_id)

    query = query.order_by(desc(SecurityRiskExceptionModel.created_at)).limit(limit).offset(offset)
    res = await db.execute(query)
    models = res.scalars().all()
    return [_to_summary(m, now) for m in models]


async def get_overdue_exceptions(
    db: AsyncSession,
    now: Optional[datetime] = None
) -> List[RiskExceptionSummary]:
    if now is None:
        now = datetime.now(timezone.utc)

    # Active exceptions past review date or past expiry
    stmt = select(SecurityRiskExceptionModel).where(
        and_(
            SecurityRiskExceptionModel.status.in_([RiskExceptionStatus.APPROVED.value, RiskExceptionStatus.PENDING_APPROVAL.value]),
            or_(
                SecurityRiskExceptionModel.expires_at <= now,
                and_(SecurityRiskExceptionModel.review_due_at.is_not(None), SecurityRiskExceptionModel.review_due_at <= now)
            )
        )
    ).order_by(desc(SecurityRiskExceptionModel.expires_at))

    res = await db.execute(stmt)
    models = res.scalars().all()
    return [_to_summary(m, now) for m in models]
