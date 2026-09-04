from typing import List
from pydantic import BaseModel


class UserPermissionsResponse(BaseModel):
    """
    Response model for user identity, role, allowed models, and dashboard access.
    Never exposes internal secrets or API keys.
    """
    user: str
    role: str
    allowed_models: List[str]
    dashboard_access: bool
