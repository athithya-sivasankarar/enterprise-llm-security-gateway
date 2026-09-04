import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from backend.db.models import (
    SecurityExposureModel,
    SecurityAssetModel,
    SecurityControlModel,
    SecurityIncidentModel,
    SecurityRegressionModel
)
from backend.observability.metrics import (
    record_exposure_created_metric,
    record_exposure_critical_metric,
    record_exposure_risk_score_metric
)
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)

# Severity to Base Weights
BASE_SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0
}

ASSET_CRITICALITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 0
}


class SecurityExposureItem(BaseModel):
    exposure_id: str
    asset_id: str
    category: str
    severity: str
    risk_score: int = Field(default=0, ge=0, le=100)
    exposure_type: str
    description: str
    source_id: Optional[str] = None
    first_detected_at: datetime
    last_detected_at: datetime
    status: str = "OPEN"


class ExposureCreateRequest(BaseModel):
    asset_id: str
    category: str
    severity: str = "HIGH"
    exposure_type: str = "CONTROL_GAP"
    description: str
    source_id: Optional[str] = None
    threat_intel_confidence: float = 0.9
    has_active_regression: bool = False
    has_open_incident: bool = False
    has_control_gap: bool = True


class ExposureResolveRequest(BaseModel):
    reason: str = "Mitigated via security policy update"


class ExposureSummary(BaseModel):
    total_exposures: int = 0
    open_exposures: int = 0
    critical_exposures: int = 0
    high_exposures: int = 0
    medium_exposures: int = 0
    low_exposures: int = 0
    resolved_exposures: int = 0
    enterprise_risk_score: int = 0
    risk_classification: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL


def classify_exposure_risk(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def calculate_exposure_risk(
    base_severity: str,
    asset_criticality: str = "HIGH",
    has_active_regression: bool = False,
    has_open_incident: bool = False,
    has_control_gap: bool = False,
    threat_intel_confidence: float = 0.0
) -> int:
    """
    Deterministic enterprise exposure risk calculation:
    Risk = Base Severity + Asset Criticality + Active Regression + Open Incident + Control Gap + Threat Intel Confidence
    Clamped to 0 - 100.
    """
    base = BASE_SEVERITY_WEIGHTS.get(base_severity.upper(), 10)
    crit = ASSET_CRITICALITY_WEIGHTS.get(asset_criticality.upper(), 10)

    score = base + crit

    if has_active_regression:
        score += 15
    if has_open_incident:
        score += 15
    if has_control_gap:
        score += 10
    if threat_intel_confidence > 0:
        score += int(round(threat_intel_confidence * 10))

    return max(0, min(100, score))


def _to_exposure_item(m: SecurityExposureModel) -> SecurityExposureItem:
    return SecurityExposureItem(
        exposure_id=m.exposure_id,
        asset_id=m.asset_id,
        category=m.category,
        severity=m.severity,
        risk_score=m.risk_score,
        exposure_type=m.exposure_type,
        description=m.description,
        source_id=m.source_id,
        first_detected_at=m.first_detected_at,
        last_detected_at=m.last_detected_at,
        status=m.status
    )


async def create_exposure(
    db: AsyncSession,
    req: ExposureCreateRequest,
    user: str = "system"
) -> SecurityExposureItem:
    """
    Create a new security exposure record with deterministic risk score.
    """
    # Fetch asset to obtain its criticality
    stmt_a = select(SecurityAssetModel).where(SecurityAssetModel.asset_id == req.asset_id)
    res_a = await db.execute(stmt_a)
    asset = res_a.scalar_one_or_none()
    asset_crit = asset.criticality if asset else "HIGH"

    risk_score = calculate_exposure_risk(
        base_severity=req.severity,
        asset_criticality=asset_crit,
        has_active_regression=req.has_active_regression,
        has_open_incident=req.has_open_incident,
        has_control_gap=req.has_control_gap,
        threat_intel_confidence=req.threat_intel_confidence
    )

    exposure_id = f"exp-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    row = SecurityExposureModel(
        exposure_id=exposure_id,
        asset_id=req.asset_id,
        category=req.category.upper(),
        severity=req.severity.upper(),
        risk_score=risk_score,
        exposure_type=req.exposure_type.upper(),
        description=req.description,
        source_id=req.source_id,
        first_detected_at=now,
        last_detected_at=now,
        status="OPEN"
    )
    db.add(row)

    # Update asset risk score if higher
    if asset and risk_score > asset.risk_score:
        asset.risk_score = risk_score
        asset.updated_at = now

    await db.commit()
    await db.refresh(row)

    record_exposure_created_metric(row.category)
    if row.severity == "CRITICAL":
        record_exposure_critical_metric()

    log_security_event(
        event_type="SECURITY_EXPOSURE_CREATED",
        request_id=f"exp-create-{exposure_id}",
        action="BLOCK" if row.severity in ("CRITICAL", "HIGH") else "ALLOW",
        response_status=201,
        user=user,
        role="security-analyst",
        threat_type=row.category
    )

    return _to_exposure_item(row)


async def list_exposures(
    db: AsyncSession,
    status_filter: Optional[str] = None,
    severity: Optional[str] = None,
    asset_id: Optional[str] = None,
    category: Optional[str] = None
) -> List[SecurityExposureItem]:
    query = select(SecurityExposureModel).order_by(desc(SecurityExposureModel.risk_score), desc(SecurityExposureModel.last_detected_at))
    if status_filter:
        query = query.where(SecurityExposureModel.status == status_filter.upper())
    if severity:
        query = query.where(SecurityExposureModel.severity == severity.upper())
    if asset_id:
        query = query.where(SecurityExposureModel.asset_id == asset_id)
    if category:
        query = query.where(SecurityExposureModel.category == category.upper())

    res = await db.execute(query)
    rows = res.scalars().all()
    return [_to_exposure_item(r) for r in rows]


async def get_exposure(db: AsyncSession, exposure_id: str) -> SecurityExposureItem:
    stmt = select(SecurityExposureModel).where(SecurityExposureModel.exposure_id == exposure_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security exposure '{exposure_id}' not found."
        )
    return _to_exposure_item(row)


async def resolve_exposure(
    db: AsyncSession,
    exposure_id: str,
    req: ExposureResolveRequest,
    user: str
) -> SecurityExposureItem:
    stmt = select(SecurityExposureModel).where(SecurityExposureModel.exposure_id == exposure_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security exposure '{exposure_id}' not found."
        )

    row.status = "RESOLVED"
    row.last_detected_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(row)

    log_security_event(
        event_type="SECURITY_EXPOSURE_RESOLVED",
        request_id=f"exp-res-{exposure_id}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="security-analyst",
        threat_type=row.category
    )

    return _to_exposure_item(row)


async def get_exposure_summary(db: AsyncSession) -> ExposureSummary:
    stmt = select(SecurityExposureModel)
    res = await db.execute(stmt)
    all_exp = res.scalars().all()

    total = len(all_exp)
    open_exp = [e for e in all_exp if e.status == "OPEN"]
    open_count = len(open_exp)
    crit = sum(1 for e in open_exp if e.severity == "CRITICAL")
    high = sum(1 for e in open_exp if e.severity == "HIGH")
    med = sum(1 for e in open_exp if e.severity == "MEDIUM")
    low = sum(1 for e in open_exp if e.severity == "LOW")
    resolved = sum(1 for e in all_exp if e.status == "RESOLVED")

    # Enterprise Exposure Risk: Max of active exposures or average
    enterprise_risk = max([e.risk_score for e in open_exp], default=0)
    classification = classify_exposure_risk(enterprise_risk)

    record_exposure_risk_score_metric(enterprise_risk)

    return ExposureSummary(
        total_exposures=total,
        open_exposures=open_count,
        critical_exposures=crit,
        high_exposures=high,
        medium_exposures=med,
        low_exposures=low,
        resolved_exposures=resolved,
        enterprise_risk_score=enterprise_risk,
        risk_classification=classification
    )
