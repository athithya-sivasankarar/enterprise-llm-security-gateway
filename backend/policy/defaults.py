import os
from backend.policy.models import (
    SecurityPolicySchema,
    RateLimitPolicy,
    InputSecurityPolicy,
    ResponseSecurityPolicy,
    CachePolicy,
    RolePolicy,
    ProviderConfig
)

DEFAULT_POLICY_VERSION = "1.0.0"


def get_default_policy() -> SecurityPolicySchema:
    """
    Build the secure default security policy matching baseline production configuration.
    Never weakens existing security thresholds.
    """
    return SecurityPolicySchema(
        policy_version=DEFAULT_POLICY_VERSION,
        rate_limit=RateLimitPolicy(
            requests=10,
            window_seconds=60
        ),
        input_security=InputSecurityPolicy(
            dlp_enabled=True,
            prompt_injection_enabled=True,
            block_threshold=60
        ),
        response_security=ResponseSecurityPolicy(
            enabled=True,
            block_threshold=80,
            sanitize_threshold=30
        ),
        cache=CachePolicy(
            enabled=True,
            ttl_seconds=300
        ),
        rbac={
            "admin": RolePolicy(
                allowed_models=[
                    "mock-model",
                    "gpt-4o-mini",
                    "gpt-4",
                    "gpt-4o",
                    "claude-3-5-sonnet-latest",
                    "claude-3-haiku-20240307"
                ],
                dashboard_access=True
            ),
            "analyst": RolePolicy(
                allowed_models=[
                    "mock-model",
                    "gpt-4o-mini",
                    "claude-3-5-sonnet-latest"
                ],
                dashboard_access=True
            ),
            "developer": RolePolicy(
                allowed_models=[
                    "mock-model"
                ],
                dashboard_access=False
            )
        },
        providers={
            "mock": ProviderConfig(
                enabled=True,
                allowed_models=["mock-model"],
                timeout_seconds=30
            ),
            "openai": ProviderConfig(
                enabled=True,
                allowed_models=["gpt-4o-mini", "gpt-4", "gpt-4o", "o1-mini"],
                timeout_seconds=30
            ),
            "anthropic": ProviderConfig(
                enabled=True,
                allowed_models=["claude-3-5-sonnet-latest", "claude-3-haiku-20240307"],
                timeout_seconds=30
            )
        }
    )
