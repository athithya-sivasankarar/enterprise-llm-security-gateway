import re
from typing import Tuple, List, Optional, Dict, Any
from pydantic import ValidationError
from backend.policy.models import SecurityPolicySchema


def validate_security_policy(policy_data: Dict[str, Any] | SecurityPolicySchema) -> Tuple[bool, Optional[SecurityPolicySchema], List[str]]:
    """
    Validate a security policy against strict schema constraints and security guardrails.
    Returns: (is_valid, parsed_policy, error_messages)
    """
    errors: List[str] = []

    # 1. Schema parsing
    policy_obj: Optional[SecurityPolicySchema] = None
    if isinstance(policy_data, SecurityPolicySchema):
        policy_obj = policy_data
    else:
        try:
            policy_obj = SecurityPolicySchema.model_validate(policy_data)
        except ValidationError as val_err:
            for err in val_err.errors():
                loc = ".".join(str(l) for l in err["loc"])
                errors.append(f"Field '{loc}': {err['msg']}")
            return False, None, errors
        except Exception as exc:
            errors.append(f"Policy schema deserialization error: {exc}")
            return False, None, errors

    # 2. Strict Semantic Version Check
    if not re.match(r"^\d+\.\d+\.\d+$", policy_obj.policy_version):
        errors.append("policy_version must follow semantic versioning (e.g. '1.0.0' or '1.2.1')")

    # 3. Mandatory Protection Guardrails (Zero-Bypass Policy)
    if not policy_obj.input_security.dlp_enabled:
        errors.append("Input DLP cannot be disabled: enterprise PII protection is mandatory.")

    if not policy_obj.input_security.prompt_injection_enabled:
        errors.append("Prompt injection defense cannot be disabled: jailbreak protection is mandatory.")

    if policy_obj.input_security.block_threshold < 60:
        errors.append("Prompt injection block_threshold cannot be below 60 (would weaken attack mitigation).")

    if not policy_obj.response_security.enabled:
        errors.append("Response security inspection cannot be disabled: secret leakage protection is mandatory.")

    if policy_obj.response_security.block_threshold < 60:
        errors.append("Response security block_threshold cannot be below 60.")

    # 4. Rate Limiting Guardrails
    if policy_obj.rate_limit.requests < 1:
        errors.append("Rate limit requests must be at least 1.")
    if policy_obj.rate_limit.window_seconds < 1:
        errors.append("Rate limit window_seconds must be at least 1.")

    # 5. RBAC Mandatory Roles Check
    required_roles = {"admin", "analyst", "developer"}
    missing_roles = required_roles - set(r.lower() for r in policy_obj.rbac.keys())
    if missing_roles:
        errors.append(f"RBAC policy is missing mandatory roles: {', '.join(sorted(missing_roles))}")

    # Ensure admin has dashboard access
    admin_policy = next((v for k, v in policy_obj.rbac.items() if k.lower() == "admin"), None)
    if admin_policy and not admin_policy.dashboard_access:
        errors.append("Admin role must retain dashboard_access=true.")

    # 6. Provider Guardrails (No raw API keys or invalid timeouts)
    for prov_name, prov_cfg in policy_obj.providers.items():
        if prov_cfg.timeout_seconds < 1 or prov_cfg.timeout_seconds > 120:
            errors.append(f"Provider '{prov_name}' timeout_seconds must be between 1 and 120.")

    if errors:
        return False, None, errors

    return True, policy_obj, []
