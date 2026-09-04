import os
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models import SecurityAlertModel
from backend.alerts.models import AlertType, AlertSeverity, AlertStatus, SecurityAlert
from backend.alerts.deduplication import has_active_alert
from backend.observability.metrics import record_security_alert_metric
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)

SCORE_ALERT_THRESHOLD = float(os.getenv("SECURITY_SCORE_ALERT_THRESHOLD", "-5.0"))


async def evaluate_campaign_alerts(
    db: AsyncSession,
    campaign_id: str,
    campaign_run_id: str,
    run_summary: Any,
    comparison: Any,
    policy_version: str = "1.0.0"
) -> List[SecurityAlert]:
    """
    Evaluate alert generation rules for an executed security assessment campaign.
    Deduplicates against existing open/acknowledged alerts.
    """
    generated_alerts: List[SecurityAlert] = []
    now = datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # Rule 1: CAMPAIGN_REGRESSION
    # -------------------------------------------------------------------------
    if comparison.regression_detected and len(comparison.regressions) > 0:
        severities = [getattr(r, "severity", "MEDIUM").upper() for r in comparison.regressions]
        highest_sev = (
            AlertSeverity.CRITICAL.value if "CRITICAL" in severities
            else AlertSeverity.HIGH.value if "HIGH" in severities
            else AlertSeverity.MEDIUM.value
        )

        test_ids = [getattr(r, "test_id", "") for r in comparison.regressions]
        title = f"Security Regression: {len(test_ids)} control(s) failed in campaign '{campaign_id}'"
        desc = (
            f"Automated assessment detected {len(test_ids)} test regressions compared to baseline. "
            f"Regressed tests: {', '.join(test_ids[:5])}. Score Delta: {comparison.score_delta}% (Policy: v{policy_version})."
        )

        if not await has_active_alert(db, campaign_id, AlertType.CAMPAIGN_REGRESSION.value, title):
            alert = await _create_and_persist_alert(
                db=db,
                campaign_id=campaign_id,
                campaign_run_id=campaign_run_id,
                alert_type=AlertType.CAMPAIGN_REGRESSION.value,
                severity=highest_sev,
                title=title,
                description=desc,
                score=run_summary.security_score,
                baseline_score=comparison.baseline_score,
                score_delta=comparison.score_delta,
                regression_count=len(comparison.regressions),
                policy_version=policy_version,
                created_at=now
            )
            generated_alerts.append(alert)

    # -------------------------------------------------------------------------
    # Rule 2: SECURITY_SCORE_DEGRADATION
    # -------------------------------------------------------------------------
    if comparison.score_delta is not None and comparison.score_delta <= SCORE_ALERT_THRESHOLD:
        deg_sev = AlertSeverity.CRITICAL.value if comparison.score_delta <= -15.0 else AlertSeverity.HIGH.value
        title = f"Security Posture Degradation: Score dropped by {abs(comparison.score_delta)}% in '{campaign_id}'"
        desc = (
            f"Gateway security score degraded from baseline {comparison.baseline_score}% "
            f"to {run_summary.security_score}% (Score Delta: {comparison.score_delta}%)."
        )

        if not await has_active_alert(db, campaign_id, AlertType.SECURITY_SCORE_DEGRADATION.value, title):
            alert = await _create_and_persist_alert(
                db=db,
                campaign_id=campaign_id,
                campaign_run_id=campaign_run_id,
                alert_type=AlertType.SECURITY_SCORE_DEGRADATION.value,
                severity=deg_sev,
                title=title,
                description=desc,
                score=run_summary.security_score,
                baseline_score=comparison.baseline_score,
                score_delta=comparison.score_delta,
                regression_count=len(comparison.regressions) if hasattr(comparison, "regressions") else 0,
                policy_version=policy_version,
                created_at=now
            )
            generated_alerts.append(alert)

    return generated_alerts


async def record_execution_error_alert(
    db: AsyncSession,
    campaign_id: str,
    error_message: str,
    campaign_run_id: Optional[str] = None,
    policy_version: str = "1.0.0"
) -> SecurityAlert:
    """
    Rule 3: Generate CAMPAIGN_EXECUTION_ERROR alert on campaign execution failure.
    """
    now = datetime.now(timezone.utc)
    title = f"Campaign Execution Failure: Campaign '{campaign_id}' encountered an error"
    desc = f"Assessment campaign failed to complete. Error: {error_message}"

    return await _create_and_persist_alert(
        db=db,
        campaign_id=campaign_id,
        campaign_run_id=campaign_run_id,
        alert_type=AlertType.CAMPAIGN_EXECUTION_ERROR.value,
        severity=AlertSeverity.HIGH.value,
        title=title,
        description=desc,
        score=None,
        baseline_score=None,
        score_delta=None,
        regression_count=0,
        policy_version=policy_version,
        created_at=now
    )


async def record_scheduler_error_alert(
    db: AsyncSession,
    campaign_id: str,
    error_message: str
) -> SecurityAlert:
    """
    Rule 4: Generate SCHEDULER_ERROR alert on persistent scheduler failure.
    """
    now = datetime.now(timezone.utc)
    title = f"Scheduler Error: Automated trigger failed for campaign '{campaign_id}'"
    desc = f"Campaign scheduler encountered an infrastructure error: {error_message}"

    return await _create_and_persist_alert(
        db=db,
        campaign_id=campaign_id,
        campaign_run_id=None,
        alert_type=AlertType.SCHEDULER_ERROR.value,
        severity=AlertSeverity.MEDIUM.value,
        title=title,
        description=desc,
        score=None,
        baseline_score=None,
        score_delta=None,
        regression_count=0,
        policy_version="1.0.0",
        created_at=now
    )


async def _create_and_persist_alert(
    db: AsyncSession,
    campaign_id: str,
    campaign_run_id: Optional[str],
    alert_type: str,
    severity: str,
    title: str,
    description: str,
    score: Optional[float],
    baseline_score: Optional[float],
    score_delta: Optional[float],
    regression_count: int,
    policy_version: str,
    created_at: datetime
) -> SecurityAlert:
    alert_id = f"alert-{uuid.uuid4().hex[:12]}"

    row = SecurityAlertModel(
        alert_id=alert_id,
        campaign_id=campaign_id,
        campaign_run_id=campaign_run_id,
        alert_type=alert_type,
        severity=severity,
        status=AlertStatus.OPEN.value,
        title=title,
        description=description,
        score=score,
        baseline_score=baseline_score,
        score_delta=score_delta,
        regression_count=regression_count,
        policy_version=policy_version,
        created_at=created_at
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    # Prometheus metric
    record_security_alert_metric(alert_type, severity)

    # SIEM security event
    log_security_event(
        event_type="SECURITY_ALERT_CREATED",
        request_id=f"alert-{alert_id}",
        action="BLOCK" if severity in ("CRITICAL", "HIGH") else "ALLOW",
        response_status=200,
        user="alert-engine",
        role="security-lead",
        threat_type=alert_type,
        risk_score=95 if severity == "CRITICAL" else 80 if severity == "HIGH" else 50
    )

    # Fail-Safe, non-blocking Incident Correlation (Step 19)
    try:
        from backend.services.incident_service import correlate_alert_safe
        await correlate_alert_safe(
            db=db,
            alert=row,
            campaign_id=campaign_id,
            campaign_run_id=campaign_run_id,
            policy_version=policy_version
        )
    except Exception as e:
        logger.error(f"Non-blocking incident correlation failed for alert '{alert_id}': {e}", exc_info=True)

    return SecurityAlert(
        alert_id=row.alert_id,
        campaign_id=row.campaign_id,
        campaign_run_id=row.campaign_run_id,
        alert_type=row.alert_type,
        severity=row.severity,
        status=row.status,
        title=row.title,
        description=row.description,
        score=row.score,
        baseline_score=row.baseline_score,
        score_delta=row.score_delta,
        regression_count=row.regression_count,
        policy_version=row.policy_version,
        created_at=row.created_at
    )
