import os
import logging
from typing import List, Set, Optional
from fastapi import HTTPException, status, Depends
from backend.security.auth import authenticate_api_key

logger = logging.getLogger(__name__)

# Default model permissions per role
DEFAULT_ADMIN_MODELS = "mock-model,gpt-4o-mini,gpt-4,gpt-4o,claude-3-5-sonnet-latest,claude-3-haiku-20240307"
DEFAULT_ANALYST_MODELS = "mock-model,gpt-4o-mini,claude-3-5-sonnet-latest"
DEFAULT_DEVELOPER_MODELS = "mock-model"

DASHBOARD_ALLOWED_ROLES = {"admin", "analyst"}


def _get_role_models(role: str) -> Set[str]:
    """
    Retrieve the set of allowed models for a given role from environment or defaults.
    """
    normalized_role = role.lower() if role else ""

    if normalized_role == "admin":
        raw = os.getenv("ADMIN_ALLOWED_MODELS", DEFAULT_ADMIN_MODELS)
    elif normalized_role == "analyst":
        raw = os.getenv("ANALYST_ALLOWED_MODELS", DEFAULT_ANALYST_MODELS)
    elif normalized_role == "developer":
        raw = os.getenv("DEVELOPER_ALLOWED_MODELS", DEFAULT_DEVELOPER_MODELS)
    else:
        raw = ""

    models = {m.strip() for m in raw.split(",") if m.strip()}
    return models


def is_model_allowed(role: str, model: str, policy=None) -> bool:
    """
    Deterministic RBAC check verifying if a role is authorized to use a target model.
    Checks active policy if provided, otherwise uses environment allowlists.
    """
    if not role or not model:
        return False

    if policy and hasattr(policy, "rbac"):
        role_cfg = policy.rbac.get(role.lower())
        if role_cfg:
            if "*" in role_cfg.allowed_models:
                return True
            return model.strip() in role_cfg.allowed_models

    allowed_models = _get_role_models(role)
    if "*" in allowed_models:
        return True

    return model.strip() in allowed_models


def get_allowed_models_for_role(role: str, policy=None) -> List[str]:
    """
    Get the list of allowed models for the specified role.
    """
    if policy and hasattr(policy, "rbac"):
        role_cfg = policy.rbac.get(role.lower())
        if role_cfg:
            return sorted(role_cfg.allowed_models)
    return sorted(list(_get_role_models(role)))


def has_dashboard_access(role: str, policy=None) -> bool:
    """
    Check if a role has permission to access SOC Dashboard telemetry.
    """
    if not role:
        return False
    if policy and hasattr(policy, "rbac"):
        role_cfg = policy.rbac.get(role.lower())
        if role_cfg is not None:
            return bool(role_cfg.dashboard_access)
    return role.lower() in DASHBOARD_ALLOWED_ROLES


def require_dashboard_access(user: dict = Depends(authenticate_api_key)) -> dict:
    """
    FastAPI dependency enforcing RBAC on SOC Dashboard endpoints.
    Allows ADMIN and ANALYST roles; blocks DEVELOPER and unknown roles with HTTP 403.
    """
    role = user.get("role", "")
    if not has_dashboard_access(role):
        logger.warning(
            "Access denied to SOC dashboard for user='%s' with role='%s'",
            user.get("user", "unknown"),
            role
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted: Your role does not have permission to access Security Operations Center analytics."
        )
    return user
