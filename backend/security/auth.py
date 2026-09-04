from fastapi import Header, HTTPException, status
from backend.observability.metrics import record_auth_metric
from backend.observability.tracing import trace_span
from backend.observability.logging import log_security_event


# API keys for development and role testing
API_KEYS = {
    "dev-key-12345": {
        "user": "developer",
        "role": "admin"
    },
    "test-key-67890": {
        "user": "security-analyst",
        "role": "analyst"
    },
    "dev-user-key-54321": {
        "user": "app-developer",
        "role": "developer"
    }
}


async def authenticate_api_key(
    x_api_key: str | None = Header(default=None)
):
    """
    Validate the X-API-Key header and record authentication telemetry.
    Never exposes raw API keys in metric labels, logs, or traces.
    """
    with trace_span("security.authentication"):
        if not x_api_key:
            record_auth_metric(success=False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API key"
            )

        user = API_KEYS.get(x_api_key)

        if not user:
            record_auth_metric(success=False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )

        record_auth_metric(success=True, role=user.get("role"))
        return user
