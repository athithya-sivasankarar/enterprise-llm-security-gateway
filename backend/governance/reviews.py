import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from backend.db.models import (
    SecurityGovernanceReviewModel,
    SecurityRiskExceptionModel,
    SecurityExposureModel,
    SecurityIncidentModel,
    SecurityRegressionModel,
    SecurityGovernanceEventModel
)
from backend.governance.models import (
    GovernanceReviewCreateRequest,
    GovernanceReview,
    GovernanceReviewType,
    GovernanceReviewStatus,
    RiskExceptionStatus
)
from backend.governance.assurance import get_control_assurance
from backend.governance.sanitizer import sanitize_governance_text, sanitize_governance_metadata

logger = logging.getLogger(__name__)


def _to_review(model: SecurityGovernanceReviewModel) -> GovernanceReview:
    return GovernanceReview(
        id=model.id,
        review_id=model.review_id,
        review_type=model.review_type,
        scope=model.scope,
        status=model.status,
        started_at=model.started_at,
        completed_at=model.completed_at,
        reviewer=model.reviewer,
        overall_score=model.overall_score,
        control_coverage=model.control_coverage,
        open_exceptions=model.open_exceptions,
        overdue_exceptions=model.overdue_exceptions,
        critical_exposures=model.critical_exposures,
        open_incidents=model.open_incidents,
        policy_version=model.policy_version or "1.0.0",
        summary=model.summary,
        created_at=model.created_at
    )


async def create_governance_review(
    db: AsyncSession,
    req: GovernanceReviewCreateRequest,
    reviewer: str = "security-officer"
) -> GovernanceReview:
    now = datetime.now(timezone.utc)
    review_id = f"REV-{uuid.uuid4().hex[:8].upper()}"
    review_type_str = req.review_type.value if hasattr(req.review_type, "value") else str(req.review_type)
    actual_reviewer = req.reviewer or reviewer

    # 1. Fetch Control Assurance
    assurances = await get_control_assurance(db)
    if assurances:
        avg_assurance_score = round(sum(a.effectiveness_score for a in assurances) / len(assurances), 1)
        avg_coverage = round(sum(a.coverage_percentage for a in assurances) / len(assurances), 1)
    else:
        avg_assurance_score = 100.0
        avg_coverage = 100.0

    # 2. Fetch Risk Exceptions
    res_exc = await db.execute(select(SecurityRiskExceptionModel))
    all_exceptions = res_exc.scalars().all()
    open_exceptions = len([e for e in all_exceptions if e.status in (RiskExceptionStatus.APPROVED.value, RiskExceptionStatus.PENDING_APPROVAL.value)])
    overdue_exceptions = len([
        e for e in all_exceptions 
        if e.status in (RiskExceptionStatus.APPROVED.value, RiskExceptionStatus.PENDING_APPROVAL.value) and (
            (e.expires_at and (e.expires_at if e.expires_at.tzinfo else e.expires_at.replace(tzinfo=timezone.utc)) <= now) or
            (e.review_due_at and (e.review_due_at if e.review_due_at.tzinfo else e.review_due_at.replace(tzinfo=timezone.utc)) <= now)
        )
    ])

    # 3. Fetch Critical Exposures
    res_exp = await db.execute(select(SecurityExposureModel).where(and_(SecurityExposureModel.status == "OPEN", SecurityExposureModel.severity == "CRITICAL")))
    crit_exposures = len(res_exp.scalars().all())

    # 4. Fetch Open Incidents
    res_inc = await db.execute(select(SecurityIncidentModel).where(SecurityIncidentModel.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])))
    open_incidents = len(res_inc.scalars().all())

    # 5. Fetch Active Regressions
    res_reg = await db.execute(select(SecurityRegressionModel).order_by(desc(SecurityRegressionModel.created_at)).limit(100))
    active_regressions = len(res_reg.scalars().all())

    # Calculate overall review score
    deductions = (crit_exposures * 15.0) + (open_incidents * 10.0) + (overdue_exceptions * 10.0) + (active_regressions * 5.0)
    overall_score = max(0.0, min(100.0, avg_assurance_score - deductions))

    # Generate executive summary narrative
    narrative = (
        f"Security Governance Review [{review_type_str}] for scope '{req.scope}'. "
        f"Overall Governance Score: {overall_score:.1f}/100. "
        f"Control Coverage: {avg_coverage:.1f}%, Control Effectiveness: {avg_assurance_score:.1f}%. "
        f"Active Findings: {open_exceptions} open risk exceptions ({overdue_exceptions} overdue), "
        f"{crit_exposures} critical exposures, {open_incidents} active incidents, and {active_regressions} regressions."
    )
    if req.notes:
        narrative += f" Reviewer Notes: {sanitize_governance_text(req.notes)}"

    sanitized_summary = sanitize_governance_text(narrative)

    model = SecurityGovernanceReviewModel(
        review_id=review_id,
        review_type=review_type_str,
        scope=req.scope,
        status=GovernanceReviewStatus.COMPLETED.value,
        started_at=now,
        completed_at=now,
        reviewer=actual_reviewer,
        overall_score=overall_score,
        control_coverage=avg_coverage,
        open_exceptions=open_exceptions,
        overdue_exceptions=overdue_exceptions,
        critical_exposures=crit_exposures,
        open_incidents=open_incidents,
        policy_version="1.0.0",
        summary=sanitized_summary,
        created_at=now
    )
    db.add(model)

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_GOVERNANCE_REVIEW_COMPLETED",
        entity_type="REVIEW",
        entity_id=review_id,
        actor=actual_reviewer,
        description=f"Completed {review_type_str} governance review '{review_id}' with score {overall_score:.1f}",
        metadata_json=sanitize_governance_metadata({
            "review_id": review_id,
            "overall_score": overall_score,
            "control_coverage": avg_coverage,
            "open_exceptions": open_exceptions
        }),
        created_at=now
    )
    db.add(event)
    await db.commit()
    await db.refresh(model)

    return _to_review(model)


async def get_governance_review(
    db: AsyncSession,
    review_id: str
) -> Optional[GovernanceReview]:
    res = await db.execute(select(SecurityGovernanceReviewModel).where(SecurityGovernanceReviewModel.review_id == review_id))
    model = res.scalar_one_or_none()
    if not model:
        return None
    return _to_review(model)


async def list_governance_reviews(
    db: AsyncSession,
    review_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> List[GovernanceReview]:
    query = select(SecurityGovernanceReviewModel)
    if review_type:
        query = query.where(SecurityGovernanceReviewModel.review_type == review_type.upper())
    if status:
        query = query.where(SecurityGovernanceReviewModel.status == status.upper())

    query = query.order_by(desc(SecurityGovernanceReviewModel.created_at)).limit(limit).offset(offset)
    res = await db.execute(query)
    models = res.scalars().all()
    return [_to_review(m) for m in models]
