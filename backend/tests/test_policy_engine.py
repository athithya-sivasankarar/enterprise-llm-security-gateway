import pytest
from backend.policy.models import SecurityPolicySchema, RateLimitPolicy, InputSecurityPolicy, ResponseSecurityPolicy, CachePolicy, RolePolicy, ProviderConfig
from backend.policy.defaults import get_default_policy, DEFAULT_POLICY_VERSION
from backend.policy.validator import validate_security_policy
from backend.policy.engine import PolicyEngine


def test_default_policy_baseline():
    """Verify that the default security policy preserves production baseline security."""
    policy = get_default_policy()
    assert policy.policy_version == DEFAULT_POLICY_VERSION
    assert policy.rate_limit.requests == 10
    assert policy.rate_limit.window_seconds == 60
    assert policy.input_security.dlp_enabled is True
    assert policy.input_security.prompt_injection_enabled is True
    assert policy.input_security.block_threshold == 60
    assert policy.response_security.enabled is True
    assert policy.response_security.block_threshold == 80
    assert policy.cache.enabled is True
    assert "admin" in policy.rbac
    assert "analyst" in policy.rbac
    assert "developer" in policy.rbac


def test_policy_engine_evaluations():
    """Test policy engine decision methods."""
    policy = get_default_policy()

    # RBAC model authorization
    assert PolicyEngine.is_model_allowed(policy, "admin", "gpt-4o") is True
    assert PolicyEngine.is_model_allowed(policy, "developer", "gpt-4o") is False
    assert PolicyEngine.is_model_allowed(policy, "developer", "mock-model") is True

    # Dashboard access
    assert PolicyEngine.has_dashboard_access(policy, "admin") is True
    assert PolicyEngine.has_dashboard_access(policy, "analyst") is True
    assert PolicyEngine.has_dashboard_access(policy, "developer") is False

    # Threshold evaluations
    assert PolicyEngine.should_block_prompt_injection(policy, 50) is False
    assert PolicyEngine.should_block_prompt_injection(policy, 60) is True
    assert PolicyEngine.should_block_prompt_injection(policy, 90) is True

    assert PolicyEngine.should_block_response(policy, 70) is False
    assert PolicyEngine.should_block_response(policy, 80) is True
    assert PolicyEngine.should_block_response(policy, 95) is True

    # Provider and cache
    assert PolicyEngine.is_provider_enabled(policy, "mock") is True
    assert PolicyEngine.is_provider_enabled(policy, "openai") is True
    assert PolicyEngine.is_cache_enabled(policy) is True
    assert PolicyEngine.get_cache_ttl(policy) == 300
    assert PolicyEngine.get_rate_limit(policy) == (10, 60)


def test_policy_validation_success():
    """Test valid policy passes validation."""
    valid_policy = get_default_policy()
    valid_policy.policy_version = "1.1.0"
    is_valid, parsed, errors = validate_security_policy(valid_policy)
    assert is_valid is True
    assert parsed is not None
    assert errors == []


def test_policy_validation_rejects_disabled_dlp():
    """Verify validation strictly rejects disabling DLP."""
    bad_policy = get_default_policy().model_dump()
    bad_policy["input_security"]["dlp_enabled"] = False
    is_valid, _, errors = validate_security_policy(bad_policy)
    assert is_valid is False
    assert any("DLP cannot be disabled" in err for err in errors)


def test_policy_validation_rejects_disabled_prompt_injection():
    """Verify validation strictly rejects disabling prompt injection defense."""
    bad_policy = get_default_policy().model_dump()
    bad_policy["input_security"]["prompt_injection_enabled"] = False
    is_valid, _, errors = validate_security_policy(bad_policy)
    assert is_valid is False
    assert any("Prompt injection defense cannot be disabled" in err for err in errors)


def test_policy_validation_rejects_lowered_block_threshold():
    """Verify validation strictly rejects injection threshold below 60."""
    bad_policy = get_default_policy().model_dump()
    bad_policy["input_security"]["block_threshold"] = 40
    is_valid, _, errors = validate_security_policy(bad_policy)
    assert is_valid is False
    assert any("block_threshold" in err for err in errors)


def test_policy_validation_rejects_missing_mandatory_roles():
    """Verify validation requires admin, analyst, and developer roles."""
    bad_policy = get_default_policy().model_dump()
    del bad_policy["rbac"]["developer"]
    is_valid, _, errors = validate_security_policy(bad_policy)
    assert is_valid is False
    assert any("missing mandatory roles" in err for err in errors)


def test_policy_validation_rejects_invalid_semantic_version():
    """Verify version must follow semantic version format."""
    bad_policy = get_default_policy().model_dump()
    bad_policy["policy_version"] = "v1-beta"
    is_valid, _, errors = validate_security_policy(bad_policy)
    assert is_valid is False
