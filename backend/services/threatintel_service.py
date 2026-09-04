import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from backend.db.models import ThreatIntelligenceModel
from backend.threatintel.models import (
    ThreatIntelItem,
    ThreatIntelCreateRequest,
    ThreatIntelSummary,
    ThreatIntelMatch,
    ThreatIntelMatchRequest,
    ThreatIntelSearchRequest
)
from backend.threatintel.normalizer import normalize_indicator
from backend.threatintel.catalog import BUILTIN_THREAT_INTEL_CATALOG
from backend.threatintel.matcher import match_threat_intel_for_category
from backend.observability.metrics import record_threat_intel_match_metric
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)


def _to_intel_item(m: ThreatIntelligenceModel) -> ThreatIntelItem:
    return ThreatIntelItem(
        intel_id=m.intel_id,
        source=m.source,
        indicator_type=m.indicator_type,
        indicator=m.indicator,
        category=m.category,
        severity=m.severity,
        confidence=m.confidence,
        description=m.description,
        first_seen_at=m.first_seen_at,
        last_seen_at=m.last_seen_at,
        expires_at=m.expires_at,
        status=m.status,
        created_at=m.created_at
    )


async def init_default_threat_intel_catalog_if_empty(db: AsyncSession) -> None:
    """
    Bootstrap the standard safe Threat Intelligence catalog idempotently.
    """
    try:
        stmt = select(ThreatIntelligenceModel.intel_id)
        res = await db.execute(stmt)
        existing_ids = set(res.scalars().all())
        now = datetime.now(timezone.utc)
        added = False
        for item in BUILTIN_THREAT_INTEL_CATALOG:
            if item["intel_id"] not in existing_ids:
                row = ThreatIntelligenceModel(
                    intel_id=item["intel_id"],
                    source=item["source"],
                    indicator_type=item["indicator_type"],
                    indicator=item["indicator"],
                    category=item["category"],
                    severity=item["severity"],
                    confidence=float(item["confidence"]),
                    description=item["description"],
                    first_seen_at=now,
                    last_seen_at=now,
                    status="ACTIVE",
                    created_at=now
                )
                db.add(row)
                added = True
        if added:
            await db.commit()
            logger.info("Initialized standard threat intelligence indicators.")
    except Exception as e:
        logger.warning(f"Failed to bootstrap threat intelligence catalog: {e}")


async def create_intelligence(
    db: AsyncSession,
    req: ThreatIntelCreateRequest,
    user: str
) -> ThreatIntelItem:
    """
    Register a new threat intelligence indicator (Admin/Analyst only).
    """
    valid, norm_indicator, err = normalize_indicator(req.indicator_type, req.indicator)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err or "Invalid threat indicator identifier."
        )

    intel_id = f"intel-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    row = ThreatIntelligenceModel(
        intel_id=intel_id,
        source=req.source.upper(),
        indicator_type=req.indicator_type.upper(),
        indicator=norm_indicator,
        category=req.category.upper(),
        severity=req.severity.upper(),
        confidence=req.confidence,
        description=req.description,
        first_seen_at=now,
        last_seen_at=now,
        status="ACTIVE",
        created_at=now
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    log_security_event(
        event_type="THREAT_INTELLIGENCE_REGISTERED",
        request_id=f"intel-reg-{intel_id}",
        action="ALLOW",
        response_status=201,
        user=user,
        role="security-analyst",
        threat_type=row.category
    )

    return _to_intel_item(row)


async def get_intelligence(db: AsyncSession, intel_id: str) -> ThreatIntelItem:
    stmt = select(ThreatIntelligenceModel).where(ThreatIntelligenceModel.intel_id == intel_id)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat intelligence item '{intel_id}' not found."
        )
    return _to_intel_item(row)


async def list_intelligence(
    db: AsyncSession,
    category: Optional[str] = None,
    indicator_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50
) -> List[ThreatIntelItem]:
    await init_default_threat_intel_catalog_if_empty(db)
    query = select(ThreatIntelligenceModel).order_by(desc(ThreatIntelligenceModel.created_at))
    if category:
        query = query.where(ThreatIntelligenceModel.category == category.upper())
    if indicator_type:
        query = query.where(ThreatIntelligenceModel.indicator_type == indicator_type.upper())
    if severity:
        query = query.where(ThreatIntelligenceModel.severity == severity.upper())

    query = query.limit(limit)
    res = await db.execute(query)
    rows = res.scalars().all()
    return [_to_intel_item(r) for r in rows]


async def get_threatintel_summary(db: AsyncSession) -> ThreatIntelSummary:
    await init_default_threat_intel_catalog_if_empty(db)
    stmt = select(ThreatIntelligenceModel)
    res = await db.execute(stmt)
    all_rows = res.scalars().all()

    total = len(all_rows)
    active = sum(1 for r in all_rows if r.status == "ACTIVE")
    crit = sum(1 for r in all_rows if r.severity == "CRITICAL" and r.status == "ACTIVE")
    high = sum(1 for r in all_rows if r.severity == "HIGH" and r.status == "ACTIVE")
    categories = {r.category for r in all_rows}
    sources = list({r.source for r in all_rows})

    return ThreatIntelSummary(
        total_indicators=total,
        active_indicators=active,
        critical_indicators=crit,
        high_indicators=high,
        categories_covered=len(categories),
        sources=sources
    )


async def match_intelligence_for_target(
    db: AsyncSession,
    req: ThreatIntelMatchRequest,
    user: str = "system"
) -> List[ThreatIntelMatch]:
    """
    Perform deterministic metadata-based threat intelligence matching.
    """
    await init_default_threat_intel_catalog_if_empty(db)
    stmt = select(ThreatIntelligenceModel).where(ThreatIntelligenceModel.status == "ACTIVE")
    res = await db.execute(stmt)
    all_intel = [
        {
            "intel_id": r.intel_id,
            "source": r.source,
            "indicator_type": r.indicator_type,
            "indicator": r.indicator,
            "category": r.category,
            "severity": r.severity,
            "confidence": r.confidence,
            "description": r.description
        } for r in res.scalars().all()
    ]

    target_category = req.category or "PROMPT_INJECTION"
    target_type = "FINDING" if req.finding_id else "INCIDENT" if req.incident_id else "TEST" if req.test_id else "ASSET" if req.asset_id else "GENERIC"
    target_id = req.finding_id or req.incident_id or req.test_id or req.asset_id or "unknown"

    matches = match_threat_intel_for_category(
        category=target_category,
        intel_items=all_intel,
        target_type=target_type,
        target_id=target_id,
        has_active_regression=bool(req.finding_id or req.incident_id),
        has_active_incident=bool(req.incident_id),
        is_critical_asset=bool(req.asset_id)
    )

    if matches:
        record_threat_intel_match_metric(target_category)
        log_security_event(
            event_type="THREAT_INTELLIGENCE_MATCHED",
            request_id=f"intel-match-{target_id}",
            action="ALLOW",
            response_status=200,
            user=user,
            role="security-analyst",
            threat_type=target_category
        )

    return matches
