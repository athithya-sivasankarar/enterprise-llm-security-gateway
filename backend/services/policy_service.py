import json
import logging
import datetime
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, desc

from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityPolicyModel
from backend.core.redis_client import redis_client
from backend.policy.models import (
    SecurityPolicySchema,
    PolicyCreateRequest,
    PolicySummaryItem
)
from backend.policy.defaults import get_default_policy, DEFAULT_POLICY_VERSION
from backend.policy.validator import validate_security_policy
from backend.observability.metrics import (
    record_policy_eval_metric,
    record_policy_fallback_metric,
    record_policy_validation_failure,
    record_policy_activation
)
from backend.observability.logging import log_security_event

logger = logging.getLogger(__name__)

REDIS_POLICY_KEY = "security_policy:active"
REDIS_POLICY_TTL_SECONDS = 60


async def get_active_policy() -> SecurityPolicySchema:
    """
    Retrieve currently active security policy with hierarchical fail-safe fallback:
    1. Try Redis cache (TTL 60s)
    2. Try PostgreSQL active policy record
    3. Fallback safely to secure built-in default policy
    Guaranteed: Observability or database failures NEVER disable security.
    """
    # 1. Try Redis Cache
    try:
        cached_json = await redis_client.get(REDIS_POLICY_KEY)
        if cached_json:
            data = json.loads(cached_json)
            record_policy_eval_metric("cache_hit")
            return SecurityPolicySchema.model_validate(data)
    except Exception as redis_exc:
        logger.debug(f"Redis policy cache lookup skipped: {redis_exc}")

    # 2. Try PostgreSQL
    try:
        async with AsyncSessionLocal() as session:
            stmt = select(SecurityPolicyModel).where(SecurityPolicyModel.is_active.is_(True)).limit(1)
            result = await session.execute(stmt)
            active_row = result.scalar_one_or_none()

            if active_row and active_row.policy_json:
                is_valid, parsed_policy, _ = validate_security_policy(active_row.policy_json)
                if is_valid and parsed_policy:
                    # Write to Redis cache asynchronously
                    try:
                        await redis_client.setex(
                            REDIS_POLICY_KEY,
                            REDIS_POLICY_TTL_SECONDS,
                            json.dumps(parsed_policy.model_dump())
                        )
                    except Exception:
                        pass

                    record_policy_eval_metric("db_hit")
                    return parsed_policy
    except Exception as db_exc:
        logger.warning(f"Failed to load active policy from database ({db_exc}), falling back safely.")
        record_policy_fallback_metric("db_error")

    # 3. Secure Built-in Fallback
    record_policy_fallback_metric("default_fallback")
    return get_default_policy()


async def create_policy(
    db: AsyncSession,
    create_req: PolicyCreateRequest,
    user: str
) -> SecurityPolicySchema:
    """
    Validate and store a new versioned security policy in PostgreSQL.
    """
    is_valid, parsed_policy, errors = validate_security_policy(create_req.policy)
    if not is_valid or not parsed_policy:
        record_policy_validation_failure()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Policy validation failed", "errors": errors}
        )

    # Check for duplicate version
    existing_stmt = select(SecurityPolicyModel).where(SecurityPolicyModel.policy_version == create_req.policy_version)
    existing_res = await db.execute(existing_stmt)
    if existing_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Security policy version '{create_req.policy_version}' already exists."
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    new_policy_row = SecurityPolicyModel(
        policy_version=create_req.policy_version,
        name=create_req.name,
        description=create_req.description,
        policy_json=parsed_policy.model_dump(),
        is_active=False,
        created_at=now,
        updated_at=now,
        created_by=user
    )

    db.add(new_policy_row)
    await db.commit()
    await db.refresh(new_policy_row)

    log_security_event(
        event_type="POLICY_CREATED",
        request_id=f"pol-create-{create_req.policy_version}",
        action="ALLOW",
        response_status=201,
        user=user,
        role="admin"
    )

    return parsed_policy


async def activate_policy(
    db: AsyncSession,
    policy_version: str,
    user: str
) -> SecurityPolicySchema:
    """
    Transactionally activate a policy version and deactivate all other versions.
    Invalidates Redis policy cache immediately upon commit.
    """
    stmt = select(SecurityPolicyModel).where(SecurityPolicyModel.policy_version == policy_version).with_for_update()
    result = await db.execute(stmt)
    target_row = result.scalar_one_or_none()

    if not target_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security policy version '{policy_version}' not found."
        )

    is_valid, parsed_policy, errors = validate_security_policy(target_row.policy_json)
    if not is_valid or not parsed_policy:
        record_policy_validation_failure()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Cannot activate invalid policy", "errors": errors}
        )

    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Deactivate all existing policies
    await db.execute(
        update(SecurityPolicyModel).values(is_active=False)
    )

    # 2. Mark target policy as active
    target_row.is_active = True
    target_row.updated_at = now
    target_row.updated_by = user
    await db.commit()
    await db.refresh(target_row)

    # 3. Invalidate Redis policy cache
    try:
        await redis_client.delete(REDIS_POLICY_KEY)
    except Exception as redis_exc:
        logger.debug(f"Redis policy cache invalidation failed: {redis_exc}")

    record_policy_activation("success")

    log_security_event(
        event_type="POLICY_ACTIVATED",
        request_id=f"pol-act-{policy_version}",
        action="ALLOW",
        response_status=200,
        user=user,
        role="admin"
    )

    return parsed_policy


async def get_policy_history(db: AsyncSession) -> List[PolicySummaryItem]:
    """
    Retrieve audit history of all security policies.
    """
    stmt = select(SecurityPolicyModel).order_by(desc(SecurityPolicyModel.updated_at))
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return [
        PolicySummaryItem(
            id=r.id,
            policy_version=r.policy_version,
            name=r.name,
            description=r.description,
            is_active=r.is_active,
            created_by=r.created_by,
            created_at=r.created_at,
            updated_at=r.updated_at
        )
        for r in rows
    ]


async def init_default_policy_if_empty(db: AsyncSession) -> None:
    """
    Bootstrap the database with default 1.0.0 policy if no policies exist.
    """
    try:
        stmt = select(SecurityPolicyModel).limit(1)
        result = await db.execute(stmt)
        if result.scalar_one_or_none() is None:
            default_pol = get_default_policy()
            now = datetime.datetime.now(datetime.timezone.utc)
            db_row = SecurityPolicyModel(
                policy_version=DEFAULT_POLICY_VERSION,
                name="Production Default Policy",
                description="Secure baseline enterprise security policy",
                policy_json=default_pol.model_dump(),
                is_active=True,
                created_at=now,
                updated_at=now,
                created_by="system"
            )
            db.add(db_row)
            await db.commit()
            logger.info("Default security policy (v1.0.0) bootstrapped and activated in database.")
    except Exception as exc:
        logger.warning(f"Could not bootstrap default policy in DB: {exc}")
