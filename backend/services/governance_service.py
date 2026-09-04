import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from backend.db.models import (
    SecurityRiskExceptionModel,
    SecurityControlAssuranceModel,
    SecurityGovernanceReviewModel,
    SecurityGovernanceEventModel,
    SecurityExposureModel,
    SecurityIncidentModel,
    SecurityRegressionModel,
    ThreatIntelligenceModel,
    SecurityControlModel
)
from backend.governance.models import (
    RiskExceptionCreateRequest,
    RiskExceptionUpdateRequest,
    RiskExceptionApprovalRequest,
    RiskExceptionRenewalRequest,
    RiskExceptionSummary,
    RiskExceptionDetail,
    ControlAssurance,
    GovernanceRiskBreakdown,
    GovernanceReviewCreateRequest,
    GovernanceReview,
    GovernanceSummary,
    GovernanceEvent,
    RiskExceptionStatus
)
from backend.governance.risk import calculate_governance_risk
from backend.governance.exceptions import (
    create_exception as exc_create,
    update_exception as exc_update,
    submit_for_approval as exc_submit,
    approve_exception as exc_approve,
    reject_exception as exc_reject,
    renew_exception as exc_renew,
    revoke_exception as exc_revoke,
    close_exception as exc_close,
    check_and_expire_exceptions as exc_check_expire,
    get_exception as exc_get,
    list_exceptions as exc_list,
    get_overdue_exceptions as exc_get_overdue
)
from backend.governance.assurance import (
    evaluate_control_assurance as asr_eval,
    get_control_assurance as asr_get,
    CORE_SECURITY_CONTROLS
)
from backend.governance.reviews import (
    create_governance_review as rev_create,
    get_governance_review as rev_get,
    list_governance_reviews as rev_list
)
from backend.observability.metrics import (
    record_governance_risk_metric,
    record_risk_exception_metric,
    set_open_exceptions_metric,
    set_overdue_exceptions_metric,
    record_exception_expired_metric,
    record_control_assurance_score_metric,
    record_control_assurance_gaps_metric,
    record_governance_review_metric
)
from backend.observability.logging import log_governance_event

logger = logging.getLogger(__name__)


async def get_governance_risk(db: AsyncSession) -> GovernanceRiskBreakdown:
    """
    Gather active enterprise findings and calculate deterministic governance risk.
    """
    now = datetime.now(timezone.utc)

    # 1. Critical & High Exposures
    res_exp_crit = await db.execute(select(SecurityExposureModel.exposure_id).where(and_(SecurityExposureModel.status == "OPEN", SecurityExposureModel.severity == "CRITICAL")))
    crit_exposures = [r[0] for r in res_exp_crit.all()]

    res_exp_high = await db.execute(select(SecurityExposureModel.exposure_id).where(and_(SecurityExposureModel.status == "OPEN", SecurityExposureModel.severity == "HIGH")))
    high_exposures = [r[0] for r in res_exp_high.all()]

    # 2. Open Critical & High Incidents
    res_inc_crit = await db.execute(select(SecurityIncidentModel.incident_id).where(and_(SecurityIncidentModel.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"]), SecurityIncidentModel.severity == "CRITICAL")))
    crit_incidents = [r[0] for r in res_inc_crit.all()]

    res_inc_high = await db.execute(select(SecurityIncidentModel.incident_id).where(and_(SecurityIncidentModel.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"]), SecurityIncidentModel.severity == "HIGH")))
    high_incidents = [r[0] for r in res_inc_high.all()]

    # 3. Control Gaps
    res_gaps = await db.execute(select(SecurityControlAssuranceModel.control_id).where(SecurityControlAssuranceModel.gap_count > 0))
    control_gaps = [r[0] for r in res_gaps.all()]

    # 4. Active Regressions
    res_reg = await db.execute(select(SecurityRegressionModel.regression_id).order_by(desc(SecurityRegressionModel.created_at)).limit(100))
    regressions = [r[0] for r in res_reg.all()]

    # 5. Overdue Exceptions
    overdue_exc_objs = await exc_get_overdue(db, now)
    overdue_exceptions = [e.exception_id for e in overdue_exc_objs]

    # 6. Affected Domains
    res_domains = await db.execute(select(SecurityExposureModel.category).where(SecurityExposureModel.status == "OPEN"))
    affected_domains = list(set([r[0] for r in res_domains.all() if r[0]]))

    # 7. Threat Intel Matches
    res_threat = await db.execute(select(ThreatIntelligenceModel.intel_id).where(ThreatIntelligenceModel.status == "ACTIVE"))
    threat_intel = [r[0] for r in res_threat.all()]

    breakdown = calculate_governance_risk(
        critical_exposures=crit_exposures,
        high_exposures=high_exposures,
        critical_incidents=crit_incidents,
        high_incidents=high_incidents,
        control_gaps=control_gaps,
        active_regressions=regressions,
        overdue_exceptions=overdue_exceptions,
        affected_domains=affected_domains,
        threat_intel_matches=threat_intel,
        now=now
    )

    record_governance_risk_metric(breakdown.overall_risk_score)
    if breakdown.overall_risk_score >= 80:
        log_governance_event(
            event_type="SECURITY_GOVERNANCE_RISK_CRITICAL",
            entity_type="RISK",
            entity_id="ENTERPRISE",
            actor="system",
            description=f"Enterprise governance risk score reached CRITICAL level: {breakdown.overall_risk_score}/100",
            metadata={"score": breakdown.overall_risk_score, "classification": breakdown.classification}
        )

    return breakdown


async def get_governance_summary(db: AsyncSession) -> GovernanceSummary:
    """
    Aggregate enterprise governance telemetry into a single unified summary.
    """
    now = datetime.now(timezone.utc)
    risk_breakdown = await get_governance_risk(db)

    assurances = await asr_get(db)
    if assurances:
        avg_assurance = round(sum(a.effectiveness_score for a in assurances) / len(assurances), 1)
        avg_coverage = round(sum(a.coverage_percentage for a in assurances) / len(assurances), 1)
        total_controls = len(assurances)
        effective_controls = len([a for a in assurances if a.last_status == "PASS"])
        control_gaps = len([a for a in assurances if a.gap_count > 0 or a.last_status == "GAP"])
    else:
        avg_assurance = 100.0
        avg_coverage = 100.0
        total_controls = len(CORE_SECURITY_CONTROLS)
        effective_controls = len(CORE_SECURITY_CONTROLS)
        control_gaps = 0

    record_control_assurance_score_metric(avg_assurance)
    record_control_assurance_gaps_metric(control_gaps)

    # Exceptions
    res_exc = await db.execute(select(SecurityRiskExceptionModel))
    all_exc = res_exc.scalars().all()
    total_exceptions = len(all_exc)
    open_exceptions = len([e for e in all_exc if e.status in (RiskExceptionStatus.APPROVED.value, RiskExceptionStatus.PENDING_APPROVAL.value)])
    approved_exceptions = len([e for e in all_exc if e.status == RiskExceptionStatus.APPROVED.value])
    pending_approval = len([e for e in all_exc if e.status == RiskExceptionStatus.PENDING_APPROVAL.value])
    expired_exceptions = len([e for e in all_exc if e.status == RiskExceptionStatus.EXPIRED.value])

    overdue_list = await exc_get_overdue(db, now)
    overdue_exceptions = len(overdue_list)

    set_open_exceptions_metric(open_exceptions)
    set_overdue_exceptions_metric(overdue_exceptions)

    # Critical Exposures & Incidents & Regressions
    res_exp = await db.execute(select(SecurityExposureModel).where(and_(SecurityExposureModel.status == "OPEN", SecurityExposureModel.severity == "CRITICAL")))
    crit_exposures = len(res_exp.scalars().all())

    res_inc = await db.execute(select(SecurityIncidentModel).where(SecurityIncidentModel.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])))
    open_incidents = len(res_inc.scalars().all())

    res_reg = await db.execute(select(SecurityRegressionModel).order_by(desc(SecurityRegressionModel.created_at)).limit(100))
    active_regressions = len(res_reg.scalars().all())



    # Latest review
    res_rev = await db.execute(select(SecurityGovernanceReviewModel).order_by(desc(SecurityGovernanceReviewModel.created_at)).limit(1))
    latest_rev = res_rev.scalar_one_or_none()
    last_review_at = latest_rev.created_at if latest_rev else None

    return GovernanceSummary(
        governance_risk_score=risk_breakdown.overall_risk_score,
        governance_risk_level=risk_breakdown.classification,
        control_assurance_score=avg_assurance,
        control_coverage_percentage=avg_coverage,
        total_controls=total_controls,
        effective_controls=effective_controls,
        control_gaps=control_gaps,
        total_exceptions=total_exceptions,
        open_exceptions=open_exceptions,
        approved_exceptions=approved_exceptions,
        pending_approval_exceptions=pending_approval,
        expired_exceptions=expired_exceptions,
        overdue_exceptions=overdue_exceptions,
        critical_exposures=crit_exposures,
        open_incidents=open_incidents,
        active_regressions=active_regressions,
        last_review_at=last_review_at,
        policy_version="1.0.0"
    )


async def create_risk_exception(
    db: AsyncSession,
    req: RiskExceptionCreateRequest,
    actor: str = "system"
) -> RiskExceptionDetail:
    detail, event = await exc_create(db, req, actor)
    record_risk_exception_metric(detail.status)
    log_governance_event(
        event_type="SECURITY_RISK_EXCEPTION_CREATED",
        entity_type="EXCEPTION",
        entity_id=detail.exception_id,
        actor=actor,
        description=f"Created risk exception '{detail.title}' for owner {detail.owner}",
        metadata={"exception_id": detail.exception_id, "severity": detail.severity, "owner": detail.owner}
    )
    return detail


async def update_risk_exception(
    db: AsyncSession,
    exception_id: str,
    req: RiskExceptionUpdateRequest,
    actor: str = "system"
) -> RiskExceptionDetail:
    return await exc_update(db, exception_id, req, actor)


async def submit_exception(
    db: AsyncSession,
    exception_id: str,
    actor: str = "system"
) -> RiskExceptionDetail:
    detail = await exc_submit(db, exception_id, actor)
    record_risk_exception_metric(detail.status)
    log_governance_event(
        event_type="SECURITY_RISK_EXCEPTION_SUBMITTED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Submitted risk exception '{exception_id}' for executive approval",
        metadata={"exception_id": exception_id}
    )
    return detail


async def approve_exception(
    db: AsyncSession,
    exception_id: str,
    req: RiskExceptionApprovalRequest,
    approver: str = "security-admin"
) -> RiskExceptionDetail:
    detail = await exc_approve(db, exception_id, req, approver)
    record_risk_exception_metric(detail.status)
    log_governance_event(
        event_type="SECURITY_RISK_EXCEPTION_APPROVED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=detail.approved_by or approver,
        description=f"Approved risk exception '{exception_id}'",
        metadata={"exception_id": exception_id, "approved_by": detail.approved_by}
    )
    return detail


async def reject_exception(
    db: AsyncSession,
    exception_id: str,
    req: RiskExceptionApprovalRequest,
    actor: str = "security-admin"
) -> RiskExceptionDetail:
    detail = await exc_reject(db, exception_id, req, actor)
    record_risk_exception_metric(detail.status)
    log_governance_event(
        event_type="SECURITY_RISK_EXCEPTION_REJECTED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Rejected risk exception '{exception_id}'",
        metadata={"exception_id": exception_id}
    )
    return detail


async def renew_exception(
    db: AsyncSession,
    exception_id: str,
    req: RiskExceptionRenewalRequest,
    actor: str = "security-admin"
) -> RiskExceptionDetail:
    detail = await exc_renew(db, exception_id, req, actor)
    record_risk_exception_metric(detail.status)
    log_governance_event(
        event_type="SECURITY_RISK_EXCEPTION_RENEWED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Renewed risk exception '{exception_id}' until {detail.expires_at.isoformat()}",
        metadata={"exception_id": exception_id, "new_expires_at": detail.expires_at.isoformat()}
    )
    return detail


async def revoke_exception(
    db: AsyncSession,
    exception_id: str,
    reason: Optional[str] = None,
    actor: str = "security-admin"
) -> RiskExceptionDetail:
    detail = await exc_revoke(db, exception_id, reason, actor)
    record_risk_exception_metric(detail.status)
    log_governance_event(
        event_type="SECURITY_RISK_EXCEPTION_REVOKED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Revoked risk exception '{exception_id}'",
        metadata={"exception_id": exception_id}
    )
    return detail


async def close_exception(
    db: AsyncSession,
    exception_id: str,
    reason: Optional[str] = None,
    actor: str = "security-admin"
) -> RiskExceptionDetail:
    detail = await exc_close(db, exception_id, reason, actor)
    record_risk_exception_metric(detail.status)
    log_governance_event(
        event_type="SECURITY_RISK_EXCEPTION_CLOSED",
        entity_type="EXCEPTION",
        entity_id=exception_id,
        actor=actor,
        description=f"Closed risk exception '{exception_id}'",
        metadata={"exception_id": exception_id}
    )
    return detail


async def get_exceptions(
    db: AsyncSession,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    owner: Optional[str] = None,
    asset_id: Optional[str] = None,
    control_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[RiskExceptionSummary]:
    return await exc_list(db, status=status, severity=severity, owner=owner, asset_id=asset_id, control_id=control_id, limit=limit, offset=offset)


async def get_exception_detail(
    db: AsyncSession,
    exception_id: str
) -> Optional[RiskExceptionDetail]:
    return await exc_get(db, exception_id)


async def get_overdue_exceptions(
    db: AsyncSession
) -> List[RiskExceptionSummary]:
    return await exc_get_overdue(db)


async def run_control_assurance(
    db: AsyncSession,
    control_id: Optional[str] = None,
    actor: str = "system"
) -> List[ControlAssurance]:
    assurances = await asr_eval(db, control_id=control_id, actor=actor)
    avg_score = round(sum(a.effectiveness_score for a in assurances) / len(assurances), 1) if assurances else 100.0
    total_gaps = sum(a.gap_count for a in assurances) if assurances else 0
    record_control_assurance_score_metric(avg_score)
    record_control_assurance_gaps_metric(total_gaps)
    log_governance_event(
        event_type="SECURITY_CONTROL_ASSURANCE_UPDATED",
        entity_type="ASSURANCE",
        entity_id=control_id or "ALL",
        actor=actor,
        description=f"Assurance evaluation completed: avg score {avg_score}%, {total_gaps} gaps",
        metadata={"control_count": len(assurances), "avg_score": avg_score, "gaps": total_gaps}
    )
    return assurances


async def get_control_assurance(
    db: AsyncSession,
    control_id: Optional[str] = None
) -> List[ControlAssurance]:
    return await asr_get(db, control_id=control_id)


async def create_governance_review(
    db: AsyncSession,
    req: GovernanceReviewCreateRequest,
    reviewer: str = "security-officer"
) -> GovernanceReview:
    review = await rev_create(db, req, reviewer=reviewer)
    record_governance_review_metric(review.review_type)
    log_governance_event(
        event_type="SECURITY_GOVERNANCE_REVIEW_COMPLETED",
        entity_type="REVIEW",
        entity_id=review.review_id,
        actor=reviewer,
        description=f"Created {review.review_type} governance review '{review.review_id}'",
        metadata={"review_id": review.review_id, "score": review.overall_score}
    )
    return review


async def get_governance_review(
    db: AsyncSession,
    review_id: str
) -> Optional[GovernanceReview]:
    return await rev_get(db, review_id)


async def list_governance_reviews(
    db: AsyncSession,
    review_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> List[GovernanceReview]:
    return await rev_list(db, review_type=review_type, status=status, limit=limit, offset=offset)


async def get_governance_events(
    db: AsyncSession,
    event_type: Optional[str] = None,
    entity_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[GovernanceEvent]:
    query = select(SecurityGovernanceEventModel)
    if event_type:
        query = query.where(SecurityGovernanceEventModel.event_type == event_type.upper())
    if entity_type:
        query = query.where(SecurityGovernanceEventModel.entity_type == entity_type.upper())

    query = query.order_by(desc(SecurityGovernanceEventModel.created_at)).limit(limit).offset(offset)
    res = await db.execute(query)
    models = res.scalars().all()
    return [
        GovernanceEvent(
            event_id=m.event_id,
            event_type=m.event_type,
            entity_type=m.entity_type,
            entity_id=m.entity_id,
            actor=m.actor,
            description=m.description,
            metadata=m.metadata_json or {},
            created_at=m.created_at
        )
        for m in models
    ]


async def check_and_expire_exceptions(
    db: AsyncSession,
    now: Optional[datetime] = None
) -> int:
    expired_count = await exc_check_expire(db, now)
    if expired_count > 0:
        for _ in range(expired_count):
            record_exception_expired_metric()
    return expired_count
