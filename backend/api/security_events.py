import uuid
import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.db.database import get_db
from backend.db.models import AuditLog
from backend.security.rbac import require_dashboard_access
from backend.schemas.security_events import SecurityEventItem, SecurityEventsResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security", tags=["SIEM Security Events"])


def determine_severity(log: AuditLog) -> str:
    """
    Map audit log characteristics to normalized SIEM severity.
    """
    if log.threat_type in ("SECRET_LEAKAGE", "MALICIOUS_CODE", "UNSAFE_CONTENT", "COMMAND_INJECTION"):
        return "CRITICAL"
    if log.injection_detected or log.threat_type in ("SYSTEM_PROMPT_EXTRACTION", "JAILBREAK"):
        return "HIGH"
    if log.action == "BLOCK" or (log.risk_score and log.risk_score >= 80):
        return "HIGH"
    if log.pii_detected or (log.risk_score and log.risk_score >= 40) or log.threat_type == "MODEL_ACCESS_DENIED":
        return "MEDIUM"
    return "LOW"


def determine_event_type(log: AuditLog) -> str:
    """
    Normalize audit record into bounded SIEM event taxonomy.
    """
    if log.threat_type == "MODEL_ACCESS_DENIED":
        return "MODEL_ACCESS_DENIED"
    if log.threat_type == "RATE_LIMIT_EXCEEDED":
        return "RATE_LIMIT_BLOCK"
    if log.threat_type == "SECRET_LEAKAGE":
        return "SECRET_LEAKAGE"
    if log.threat_type == "UNSAFE_CONTENT":
        return "UNSAFE_CONTENT"
    if log.injection_detected or log.threat_type in ("SYSTEM_PROMPT_EXTRACTION", "JAILBREAK"):
        return "PROMPT_INJECTION"
    if log.pii_detected:
        return "PII_DETECTED"
    if log.action == "BLOCK":
        return "SECURITY_BLOCK"
    return "SECURITY_AUDIT"


@router.get("/events", response_model=SecurityEventsResponse)
async def get_security_events(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    event_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user_data: dict = Depends(require_dashboard_access)
):
    """
    Export normalized, SIEM-ready security events for SOC integration.
    Strictly restricted to admin and analyst roles.
    Never exposes raw prompts, responses, or API keys.
    """
    try:
        query = select(AuditLog).order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit)
        result = await db.execute(query)
        records = result.scalars().all()

        events = []
        for r in records:
            e_type = determine_event_type(r)
            sev = determine_severity(r)

            # Apply query filters if requested
            if event_type and e_type.upper() != event_type.upper():
                continue
            if severity and sev.upper() != severity.upper():
                continue

            events.append(
                SecurityEventItem(
                    event_id=f"evt-{r.request_id[:8]}-{r.id}",
                    timestamp=r.timestamp,
                    request_id=r.request_id,
                    event_type=e_type,
                    severity=sev,
                    user=r.user,
                    role=r.role,
                    model=r.model,
                    provider=r.provider or "mock",
                    action=r.action,
                    risk_score=r.risk_score or 0,
                    threat_type=r.threat_type,
                    response_status=r.response_status or 200,
                    latency_ms=r.latency_ms,
                    cache_hit=bool(r.cache_hit),
                    detected_entities=r.detected_entities or []
                )
            )

        return SecurityEventsResponse(
            events=events,
            total=len(events)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch SIEM security events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve SIEM security events"
        )
