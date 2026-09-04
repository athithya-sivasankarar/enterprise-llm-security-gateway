import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.database import get_db
from backend.db.models import SecurityPolicyModel
from backend.security.auth import authenticate_api_key
from backend.security.rbac import require_dashboard_access
from backend.policy.models import (
    SecurityPolicySchema,
    PolicyCreateRequest,
    PolicyValidationResponse,
    PolicyHistoryResponse,
    PolicyActiveResponse
)
from backend.policy.validator import validate_security_policy
from backend.services.policy_service import (
    get_active_policy,
    create_policy,
    activate_policy,
    get_policy_history
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/policies", tags=["Security Policies"])


def require_admin_role(user: dict = Depends(authenticate_api_key)) -> dict:
    """
    FastAPI dependency restricting policy modifications strictly to admin role.
    """
    role = (user.get("role") or "").lower()
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only administrators can create or activate security policies."
        )
    return user


@router.get("", response_model=PolicyHistoryResponse)
async def list_policies(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    List all security policies in the version registry.
    Accessible to admin and analyst roles.
    """
    history = await get_policy_history(db)
    return PolicyHistoryResponse(policies=history, total=len(history))


@router.get("/active", response_model=PolicyActiveResponse)
async def get_active_security_policy(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve the currently active security policy.
    Accessible to admin and analyst roles.
    """
    active_policy = await get_active_policy()
    
    # Query metadata for active policy
    stmt = select(SecurityPolicyModel).where(SecurityPolicyModel.policy_version == active_policy.policy_version)
    res = await db.execute(stmt)
    row = res.scalar_one_or_none()

    name = row.name if row else "Production Default Policy"
    description = row.description if row else "Default built-in security policy"
    updated_at = row.updated_at if row else active_policy.rbac.get("admin")
    updated_by = row.created_by if row else "system"

    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)

    return PolicyActiveResponse(
        policy_version=active_policy.policy_version,
        name=name,
        description=description,
        is_active=True,
        policy=active_policy,
        updated_at=row.updated_at if row else now,
        updated_by=row.updated_by if row and hasattr(row, "updated_by") else "system"
    )


@router.get("/history", response_model=PolicyHistoryResponse)
async def get_policy_audit_history(
    user: dict = Depends(require_dashboard_access),
    db: AsyncSession = Depends(get_db)
):
    """
    Audit log of all policy versions, updates, and activations.
    """
    history = await get_policy_history(db)
    return PolicyHistoryResponse(policies=history, total=len(history))


@router.post("/validate", response_model=PolicyValidationResponse)
async def validate_policy_endpoint(
    policy_data: dict,
    user: dict = Depends(require_dashboard_access)
):
    """
    Dry-run validation of a security policy schema without activating or persisting.
    """
    is_valid, parsed, errors = validate_security_policy(policy_data)
    version = parsed.policy_version if parsed else policy_data.get("policy_version", "unknown")
    return PolicyValidationResponse(
        valid=is_valid,
        policy_version=version,
        errors=errors
    )


@router.post("", response_model=SecurityPolicySchema, status_code=status.HTTP_201_CREATED)
async def create_new_policy(
    req: PolicyCreateRequest,
    user: dict = Depends(require_admin_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new versioned security policy. Admin only.
    """
    username = user.get("user", "admin")
    return await create_policy(db, req, username)


@router.post("/{policy_version}/activate", response_model=SecurityPolicySchema)
@router.put("/{policy_version}/activate", response_model=SecurityPolicySchema)
async def activate_policy_endpoint(
    policy_version: str,
    user: dict = Depends(require_admin_role),
    db: AsyncSession = Depends(get_db)
):
    """
    Transactionally activate or rollback to a target security policy version. Admin only.
    """
    username = user.get("user", "admin")
    return await activate_policy(db, policy_version, username)
