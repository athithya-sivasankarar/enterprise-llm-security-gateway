import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, desc

from backend.db.models import (
    SecurityIncidentModel,
    SecurityIncidentEventModel,
    SecurityAlertModel,
    SecurityRegressionModel,
    SecurityTestResultModel,
    SecurityTestFindingModel,
    SecurityCampaignRunModel
)
from backend.incidents.scoring import calculate_incident_risk, classify_incident_severity
from backend.incidents.sanitizer import sanitize_incident_metadata, sanitize_incident_text

logger = logging.getLogger(__name__)

CORRELATION_WINDOW_MINUTES = 30


def generate_alert_correlation_fingerprint(
    campaign_id: Optional[str],
    campaign_run_id: Optional[str],
    category: Optional[str] = None,
    policy_version: Optional[str] = "1.0.0"
) -> str:
    """
    Generate deterministic SHA-256 fingerprint for correlating alerts and incidents.
    """
    raw = f"{campaign_id or 'none'}|{campaign_run_id or 'none'}|{category or 'none'}|{policy_version or '1.0.0'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


async def find_correlatable_incident(
    db: AsyncSession,
    campaign_id: Optional[str],
    campaign_run_id: Optional[str],
    source_alert_id: Optional[str] = None,
    created_at: Optional[datetime] = None
) -> Optional[SecurityIncidentModel]:
    """
    Find existing open/investigating incident matching correlation criteria within the 30-minute window.
    """
    now = created_at or datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    # 1. Match by direct campaign_run_id if present
    if campaign_run_id:
        stmt = select(SecurityIncidentModel).where(
            and_(
                SecurityIncidentModel.campaign_run_id == campaign_run_id,
                SecurityIncidentModel.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])
            )
        ).order_by(desc(SecurityIncidentModel.created_at))
        res = await db.execute(stmt)
        matched = res.scalars().first()
        if matched:
            return matched

    # 2. Match by campaign_id within 30-minute correlation window
    if campaign_id:
        stmt = select(SecurityIncidentModel).where(
            and_(
                SecurityIncidentModel.campaign_id == campaign_id,
                SecurityIncidentModel.created_at >= window_start,
                SecurityIncidentModel.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])
            )
        ).order_by(desc(SecurityIncidentModel.created_at))
        res = await db.execute(stmt)
        matched = res.scalars().first()
        if matched:
            return matched

    # 3. Match by source_alert_id
    if source_alert_id:
        stmt = select(SecurityIncidentModel).where(
            SecurityIncidentModel.source_alert_id == source_alert_id
        )
        res = await db.execute(stmt)
        matched = res.scalars().first()
        if matched:
            return matched

    return None


async def evaluate_incident_correlation_factors(
    db: AsyncSession,
    campaign_id: Optional[str],
    campaign_run_id: Optional[str],
    alert: Optional[SecurityAlertModel] = None
) -> Dict[str, Any]:
    """
    Evaluate regression counts, findings severities, degraded posture, repeated failures,
    and multiple domain presence for correlation & deterministic risk scoring.
    """
    findings_severities: List[str] = []
    categories: List[str] = []
    has_regressions = False
    is_posture_degraded = False
    is_repeated_event = False

    # Check alert details
    if alert:
        if alert.severity:
            findings_severities.append(alert.severity)
        if alert.alert_type == "CAMPAIGN_REGRESSION" or (alert.regression_count and alert.regression_count > 0):
            has_regressions = True
        if alert.alert_type == "SECURITY_SCORE_DEGRADATION" or (alert.score_delta and alert.score_delta < -5.0):
            is_posture_degraded = True

    # Query regressions if campaign_run_id is available
    if campaign_run_id:
        stmt_reg = select(SecurityRegressionModel).where(
            SecurityRegressionModel.campaign_run_id == campaign_run_id
        )
        res_reg = await db.execute(stmt_reg)
        regressions = res_reg.scalars().all()
        if regressions:
            has_regressions = True
            for r in regressions:
                findings_severities.append(r.severity)
                if r.category:
                    categories.append(r.category)

            # Rule 3: Check if same test_id failed in previous runs (repeated failure)
            test_ids = [r.test_id for r in regressions if r.test_id]
            if test_ids:
                stmt_prev = select(SecurityRegressionModel).where(
                    and_(
                        SecurityRegressionModel.test_id.in_(test_ids),
                        SecurityRegressionModel.campaign_run_id != campaign_run_id
                    )
                ).limit(1)
                res_prev = await db.execute(stmt_prev)
                if res_prev.scalars().first():
                    is_repeated_event = True

    # Query campaign run status
    if campaign_run_id:
        stmt_crun = select(SecurityCampaignRunModel).where(
            SecurityCampaignRunModel.campaign_run_id == campaign_run_id
        )
        res_crun = await db.execute(stmt_crun)
        crun = res_crun.scalar_one_or_none()
        if crun:
            if crun.regression_detected:
                has_regressions = True
            if crun.score_delta and crun.score_delta < -5.0:
                is_posture_degraded = True

    risk_score = calculate_incident_risk(
        findings_severities=findings_severities,
        has_regressions=has_regressions,
        is_posture_degraded=is_posture_degraded,
        is_repeated_event=is_repeated_event,
        categories=categories,
        base_severity=alert.severity if alert else "MEDIUM"
    )

    severity = classify_incident_severity(risk_score)
    priority = "P1" if severity == "CRITICAL" else "P2" if severity == "HIGH" else "P3" if severity == "MEDIUM" else "P4"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "priority": priority,
        "has_regressions": has_regressions,
        "is_posture_degraded": is_posture_degraded,
        "is_repeated_event": is_repeated_event,
        "categories": list(set(categories))
    }
