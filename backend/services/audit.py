import logging
from typing import List, Optional
from backend.db.database import AsyncSessionLocal
from backend.db.models import AuditLog

logger = logging.getLogger(__name__)


async def record_audit_log(
    request_id: str,
    user: str,
    role: str,
    model: str,
    action: str,
    risk_score: int,
    pii_detected: bool,
    injection_detected: bool,
    threat_type: Optional[str],
    response_status: int,
    latency_ms: float,
    detected_entities: Optional[List[str]] = None,
    response_risk_score: Optional[int] = None,
    response_action: Optional[str] = None,
    response_threat_type: Optional[str] = None,
    cache_hit: bool = False,
    provider: Optional[str] = "mock",
    policy_version: Optional[str] = "1.0.0"
) -> bool:
    """
    Safely persist a security audit record to PostgreSQL with policy version tracking.
    STRICT PRIVACY: Persists security metadata only. Never stores raw PII or raw prompts/responses.
    Fails safely with logging if the database is unavailable without crashing the application.
    """
    if detected_entities is None:
        detected_entities = []

    audit_entry = AuditLog(
        request_id=request_id,
        user=user,
        role=role,
        model=model,
        provider=provider or "mock",
        action=action,
        risk_score=risk_score,
        pii_detected=pii_detected,
        injection_detected=injection_detected,
        threat_type=threat_type,
        response_status=response_status,
        latency_ms=latency_ms,
        detected_entities=detected_entities,
        response_risk_score=response_risk_score if response_risk_score is not None else 0,
        response_action=response_action,
        response_threat_type=response_threat_type,
        cache_hit=cache_hit,
        policy_version=policy_version or "1.0.0"
    )

    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                session.add(audit_entry)
            await session.commit()

        logger.info(
            "Audit record saved: request_id=%s, user=%s, provider=%s, policy_version=%s, action=%s, risk_score=%d, cache_hit=%s, latency=%.2fms",
            request_id,
            user,
            provider,
            policy_version,
            action,
            risk_score,
            cache_hit,
            latency_ms
        )
        return True
    except Exception as exc:
        logger.error(
            "Failed to save audit log for request_id=%s: %s (Audit logging compliance warning)",
            request_id,
            exc
        )
        return False
