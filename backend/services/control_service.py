import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from backend.db.models import SecurityControlModel
from backend.control_coverage.models import (
    SecurityControlItem,
    ControlCoverageSummary,
    ControlGapItem
)
from backend.control_coverage.engine import (
    STANDARD_SECURITY_CONTROLS,
    evaluate_security_control_coverage
)
from backend.observability.metrics import (
    record_control_coverage_metric,
    record_control_gap_metric
)
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)


def _to_control_item(m: SecurityControlModel) -> SecurityControlItem:
    return SecurityControlItem(
        control_id=m.control_id,
        name=m.name,
        description=m.description,
        domain=m.domain,
        control_type=m.control_type,
        enabled=m.enabled,
        implementation_status=m.implementation_status,
        coverage_percentage=m.coverage_percentage,
        last_tested_at=m.last_tested_at,
        last_test_status=m.last_test_status,
        policy_version=m.policy_version
    )


async def init_default_controls_if_empty(db: AsyncSession) -> None:
    """
    Bootstrap standard 14 security controls idempotently if missing.
    """
    try:
        stmt = select(SecurityControlModel.control_id)
        res = await db.execute(stmt)
        existing_ids = set(res.scalars().all())
        now = datetime.now(timezone.utc)
        added = False
        for ctrl in STANDARD_SECURITY_CONTROLS:
            if ctrl["control_id"] not in existing_ids:
                row = SecurityControlModel(
                    control_id=ctrl["control_id"],
                    name=ctrl["name"],
                    description=ctrl["description"],
                    domain=ctrl["domain"],
                    control_type=ctrl.get("control_type", "PREVENTIVE"),
                    enabled=True,
                    implementation_status="IMPLEMENTED",
                    coverage_percentage=100.0,
                    last_tested_at=now,
                    last_test_status="PASS",
                    policy_version="1.0.0",
                    created_at=now,
                    updated_at=now
                )
                db.add(row)
                added = True
        if added:
            await db.commit()
            logger.info("Initialized standard security controls.")
    except Exception as e:
        logger.warning(f"Failed to bootstrap security controls: {e}")


async def list_controls(
    db: AsyncSession,
    domain: Optional[str] = None
) -> List[SecurityControlItem]:
    await init_default_controls_if_empty(db)
    query = select(SecurityControlModel).order_by(SecurityControlModel.control_id)
    if domain:
        query = query.where(SecurityControlModel.domain == domain.upper())

    res = await db.execute(query)
    rows = res.scalars().all()
    return [_to_control_item(r) for r in rows]


async def get_control(db: AsyncSession, control_id: str) -> SecurityControlItem:
    await init_default_controls_if_empty(db)
    stmt = select(SecurityControlModel).where(SecurityControlModel.control_id == control_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security control '{control_id}' not found."
        )
    return _to_control_item(row)


async def get_control_coverage(
    db: AsyncSession,
    run_id: Optional[str] = None
) -> ControlCoverageSummary:
    """
    Calculate real-time control coverage, pass rates, and gaps.
    """
    await init_default_controls_if_empty(db)
    summary = await evaluate_security_control_coverage(db, run_id=run_id)

    # Record Prometheus metrics
    record_control_coverage_metric(summary.overall_coverage_pct)
    record_control_gap_metric(summary.control_gaps_count)

    # Emit SIEM event if critical control gaps exist
    if summary.gaps:
        crit_gaps = [g for g in summary.gaps if g.severity == "CRITICAL"]
        if crit_gaps:
            log_security_event(
                event_type="SECURITY_CONTROL_GAP_DETECTED",
                request_id=f"ctrl-gap-{crit_gaps[0].control_id}",
                action="BLOCK",
                response_status=200,
                user="control-engine",
                role="security-service",
                threat_type=crit_gaps[0].domain
            )

    return summary


async def get_control_gaps(
    db: AsyncSession,
    run_id: Optional[str] = None
) -> List[ControlGapItem]:
    summary = await get_control_coverage(db, run_id=run_id)
    return summary.gaps
