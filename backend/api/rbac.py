from fastapi import APIRouter, Depends
from backend.security.auth import authenticate_api_key
from backend.security.rbac import get_allowed_models_for_role, has_dashboard_access
from backend.schemas.rbac import UserPermissionsResponse

router = APIRouter(
    tags=["RBAC & Identity"]
)


@router.get("/api/auth/me", response_model=UserPermissionsResponse)
@router.get("/api/rbac/permissions", response_model=UserPermissionsResponse)
async def get_current_user_permissions(
    user: dict = Depends(authenticate_api_key)
):
    """
    Return the authenticated user's role, model allowlist, and dashboard permission.
    Never exposes internal credentials or other users' profiles.
    """
    username = user.get("user", "unknown")
    role = user.get("role", "unknown")

    allowed_models = get_allowed_models_for_role(role)
    dashboard_access = has_dashboard_access(role)

    return UserPermissionsResponse(
        user=username,
        role=role,
        allowed_models=allowed_models,
        dashboard_access=dashboard_access
    )
