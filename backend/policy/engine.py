import logging
from typing import Tuple, List
from backend.policy.models import SecurityPolicySchema

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Central evaluation engine applying versioned policy rules to security checkpoints.
    """

    @staticmethod
    def is_model_allowed(policy: SecurityPolicySchema, role: str, model: str) -> bool:
        """
        Check if role is authorized to use target model according to policy.
        """
        if not role or not model:
            return False

        normalized_role = role.lower()
        role_cfg = policy.rbac.get(normalized_role)
        if not role_cfg:
            return False

        if "*" in role_cfg.allowed_models:
            return True

        return model.strip() in role_cfg.allowed_models

    @staticmethod
    def has_dashboard_access(policy: SecurityPolicySchema, role: str) -> bool:
        """
        Check if role has dashboard access according to policy.
        """
        if not role:
            return False
        role_cfg = policy.rbac.get(role.lower())
        return bool(role_cfg and role_cfg.dashboard_access)

    @staticmethod
    def get_allowed_models_for_role(policy: SecurityPolicySchema, role: str) -> List[str]:
        """
        Return the list of allowed models for a role.
        """
        role_cfg = policy.rbac.get(role.lower()) if role else None
        return sorted(role_cfg.allowed_models) if role_cfg else []

    @staticmethod
    def should_block_prompt_injection(policy: SecurityPolicySchema, risk_score: int) -> bool:
        """
        Determine if prompt injection risk score meets or exceeds block threshold.
        """
        threshold = policy.input_security.block_threshold
        return risk_score >= threshold

    @staticmethod
    def should_block_response(policy: SecurityPolicySchema, risk_score: int) -> bool:
        """
        Determine if response risk score meets or exceeds output block threshold.
        """
        threshold = policy.response_security.block_threshold
        return risk_score >= threshold

    @staticmethod
    def is_provider_enabled(policy: SecurityPolicySchema, provider: str) -> bool:
        """
        Check if provider is enabled in the active policy.
        """
        if not provider:
            return False
        prov_cfg = policy.providers.get(provider.lower())
        return prov_cfg.enabled if prov_cfg else False

    @staticmethod
    def is_cache_enabled(policy: SecurityPolicySchema) -> bool:
        """
        Check if Redis semantic caching is enabled in policy.
        """
        return policy.cache.enabled

    @staticmethod
    def get_cache_ttl(policy: SecurityPolicySchema) -> int:
        """
        Return cache TTL seconds from policy.
        """
        return policy.cache.ttl_seconds

    @staticmethod
    def get_rate_limit(policy: SecurityPolicySchema) -> Tuple[int, int]:
        """
        Return (requests, window_seconds) from policy.
        """
        return policy.rate_limit.requests, policy.rate_limit.window_seconds
