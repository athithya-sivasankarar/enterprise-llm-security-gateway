import time
import json
import logging
from typing import Tuple, Optional, Dict, Any
import httpx

from backend.redteam.models import SecurityTestCase, SecurityTestResult, SecurityTestFinding
from backend.redteam.categories import TestCategory, TestStatus, SeverityLevel
from backend.redteam.assertions import evaluate_assertion
from backend.security.rate_limiter import check_rate_limit
from backend.services.semantic_cache import get_cached_response, cache_response, generate_cache_key
from backend.core.redis_client import redis_client

logger = logging.getLogger(__name__)

ROLE_API_KEYS = {
    "admin": "dev-key-12345",
    "analyst": "test-key-67890",
    "developer": "dev-user-key-54321",
    "invalid": "invalid-key-99999",
    "none": None
}


async def execute_test_case(
    client: httpx.AsyncClient,
    test_case: SecurityTestCase,
    run_id: str,
    policy_version: str = "1.0.0"
) -> Tuple[SecurityTestResult, Optional[SecurityTestFinding]]:
    """
    Safely execute an individual security validation test case.
    Dispatches specialized sequences (Rate Limiting, Cache Isolation) or standard HTTP requests.
    """
    start_time = time.perf_counter()

    # 1. Specialized Rate Limit Sequence
    if test_case.assertion_type == "rate_limit_sequence":
        return await _execute_rate_limit_sequence(test_case, run_id, policy_version)

    # 2. Specialized Semantic Cache Isolation Sequence
    if test_case.assertion_type == "cache_isolation_sequence":
        return await _execute_cache_isolation_sequence(test_case, run_id, policy_version)

    # 3. Standard HTTP Gateway Request Execution
    # Ensure fresh execution without stale cache hits
    if test_case.prompt:
        try:
            target_role = test_case.api_key_role if test_case.api_key_role in ("admin", "analyst", "developer") else "admin"
            ck = generate_cache_key(test_case.prompt, test_case.model, target_role, "mock")
            await redis_client.delete(ck)
        except Exception:
            pass

    headers: Dict[str, str] = {
        "Content-Type": "application/json"
    }
    
    if test_case.api_key_role and test_case.api_key_role != "none":
        api_key = ROLE_API_KEYS.get(test_case.api_key_role)
        if api_key:
            headers["X-API-Key"] = api_key

    if test_case.custom_headers:
        headers.update(test_case.custom_headers)

    payload = None
    if test_case.method == "POST":
        if test_case.custom_payload:

            payload = test_case.custom_payload
        else:
            payload = {
                "prompt": test_case.prompt or "Health check verification",
                "model": test_case.model
            }

    try:
        if test_case.method == "POST":
            response = await client.post(
                test_case.endpoint,
                json=payload,
                headers=headers,
                timeout=10.0
            )
        elif test_case.method == "GET":
            response = await client.get(
                test_case.endpoint,
                headers=headers,
                timeout=10.0
            )
        else:
            response = await client.request(
                test_case.method,
                test_case.endpoint,
                json=payload,
                headers=headers,
                timeout=10.0
            )

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        status_code = response.status_code

        try:
            response_body = response.json()
        except Exception:
            response_body = response.text

        return evaluate_assertion(
            test_case=test_case,
            run_id=run_id,
            status_code=status_code,
            response_body=response_body,
            latency_ms=latency_ms,
            policy_version=policy_version,
            error_message=None
        )
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.warning(f"Error executing security test {test_case.test_id}: {exc}")
        return evaluate_assertion(
            test_case=test_case,
            run_id=run_id,
            status_code=0,
            response_body=None,
            latency_ms=latency_ms,
            policy_version=policy_version,
            error_message=str(exc)
        )


async def _execute_rate_limit_sequence(
    test_case: SecurityTestCase,
    run_id: str,
    policy_version: str
) -> Tuple[SecurityTestResult, Optional[SecurityTestFinding]]:
    """
    Deterministic, low-rate validation sequence (limit=3 req/60s).
    Validates 3 allowed requests and HTTP 429 on 4th request.
    Cleans up synthetic Redis key upon completion.
    """
    start_time = time.perf_counter()
    synthetic_key = f"redteam-rate-test-{run_id[:8]}"
    redis_key = f"rate_limit:{synthetic_key}"
    limit = 3
    window = 60

    passed = True
    failure_reasons = []

    try:
        # Step 1: First 3 requests should be allowed
        for i in range(1, limit + 1):
            allowed = await check_rate_limit(api_key=synthetic_key, role="developer", limit=limit, window_seconds=window)
            if not allowed:
                passed = False
                failure_reasons.append(f"Request {i}/{limit} was unexpectedly blocked before threshold")

        # Step 2: 4th request should raise HTTP 429
        blocked_429 = False
        try:
            await check_rate_limit(api_key=synthetic_key, role="developer", limit=limit, window_seconds=window)
        except Exception as exc:
            if hasattr(exc, "status_code") and exc.status_code == 429:
                blocked_429 = True

        if not blocked_429:
            passed = False
            failure_reasons.append("4th request did not raise HTTP 429 Rate Limit Exceeded")

    except Exception as exc:
        passed = False
        failure_reasons.append(f"Rate limiting infrastructure error: {exc}")
    finally:
        # Clean up synthetic rate limit key safely
        try:
            await redis_client.delete(redis_key)
        except Exception:
            pass

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    status_enum = TestStatus.PASS if passed else TestStatus.FAIL

    result = SecurityTestResult(
        run_id=run_id,
        test_id=test_case.test_id,
        category=test_case.category.value,
        status=status_enum.value,
        severity=test_case.severity.value,
        expected_action="BLOCK",
        actual_action="BLOCK" if blocked_429 else "ALLOW",
        expected_status=429,
        actual_status=429 if blocked_429 else 200,
        threat_type="RATE_LIMIT_EXCEEDED",
        latency_ms=latency_ms,
        policy_version=policy_version,
        error_message="; ".join(failure_reasons) if failure_reasons else None
    )

    finding = None
    if not passed:
        finding = SecurityTestFinding(
            finding_id=f"find-{run_id[:8]}-{test_case.test_id}",
            run_id=run_id,
            test_id=test_case.test_id,
            category=test_case.category.value,
            severity=test_case.severity.value,
            title=f"Rate Limiting Failure: {test_case.name}",
            description=f"Controlled rate limiting test failed: {'; '.join(failure_reasons)}",
            expected_behavior="HTTP 429 on threshold exceeded",
            actual_behavior="Requests not rate limited properly",
            endpoint=test_case.endpoint,
            policy_version=policy_version
        )

    return result, finding


async def _execute_cache_isolation_sequence(
    test_case: SecurityTestCase,
    run_id: str,
    policy_version: str
) -> Tuple[SecurityTestResult, Optional[SecurityTestFinding]]:
    """
    Deterministic cache isolation test across roles, models, and providers.
    Verifies that cache keys are strictly isolated and cleans up test keys.
    """
    start_time = time.perf_counter()
    test_prompt = f"Synthetic cache isolation test prompt {run_id[:8]}"
    synthetic_resp = "Synthetic response for cache isolation test"

    passed = True
    failure_reasons = []

    try:
        # Step 1: Write cache entry for admin + mock-model + mock provider
        await cache_response(
            prompt=test_prompt,
            model="mock-model",
            user_role="admin",
            response=synthetic_resp,
            provider="mock"
        )

        # Step 2: Analyst role with same prompt & model must MISS (role isolation)
        analyst_hit = await get_cached_response(
            prompt=test_prompt,
            model="mock-model",
            user_role="analyst",
            provider="mock"
        )
        if analyst_hit is not None:
            passed = False
            failure_reasons.append("Cache Isolation Breach: Analyst role received Admin cached response")

        # Step 3: Admin role with different model must MISS (model isolation)
        model_hit = await get_cached_response(
            prompt=test_prompt,
            model="gpt-4o",
            user_role="admin",
            provider="mock"
        )
        if model_hit is not None:
            passed = False
            failure_reasons.append("Cache Isolation Breach: Different model received cached response")

        # Step 4: Admin role with different provider must MISS (provider isolation)
        provider_hit = await get_cached_response(
            prompt=test_prompt,
            model="mock-model",
            user_role="admin",
            provider="openai"
        )
        if provider_hit is not None:
            passed = False
            failure_reasons.append("Cache Isolation Breach: Different provider received cached response")

        # Step 5: Admin role with matching parameters must HIT
        admin_hit = await get_cached_response(
            prompt=test_prompt,
            model="mock-model",
            user_role="admin",
            provider="mock"
        )
        if admin_hit != synthetic_resp:
            passed = False
            failure_reasons.append("Cache retrieval failed for identical role, model, and provider")

    except Exception as exc:
        passed = False
        failure_reasons.append(f"Cache isolation test exception: {exc}")
    finally:
        # Clean up targeted synthetic cache keys safely
        try:
            admin_key = generate_cache_key(test_prompt, "mock-model", "admin", "mock")
            await redis_client.delete(admin_key)
        except Exception:
            pass

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
    status_enum = TestStatus.PASS if passed else TestStatus.FAIL

    result = SecurityTestResult(
        run_id=run_id,
        test_id=test_case.test_id,
        category=test_case.category.value,
        status=status_enum.value,
        severity=test_case.severity.value,
        expected_action="ALLOW",
        actual_action="ALLOW",
        expected_status=200,
        actual_status=200,
        threat_type=None,
        latency_ms=latency_ms,
        policy_version=policy_version,
        error_message="; ".join(failure_reasons) if failure_reasons else None
    )

    finding = None
    if not passed:
        finding = SecurityTestFinding(
            finding_id=f"find-{run_id[:8]}-{test_case.test_id}",
            run_id=run_id,
            test_id=test_case.test_id,
            category=test_case.category.value,
            severity=test_case.severity.value,
            title=f"Cache Isolation Failure: {test_case.name}",
            description=f"Semantic cache isolation failure: {'; '.join(failure_reasons)}",
            expected_behavior="Strict isolation across role, model, and provider",
            actual_behavior="Cache cross-contamination detected",
            endpoint="/api/chat",
            policy_version=policy_version
        )

    return result, finding
