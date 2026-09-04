import time
import uuid
import logging
from fastapi import APIRouter, Depends, Header, HTTPException, Response, status

from backend.schemas.chat import ChatRequest, ChatResponse, SecurityInfo
from backend.security.auth import authenticate_api_key
from backend.security.rbac import is_model_allowed
from backend.security.rate_limiter import check_rate_limit
from backend.security.dlp import inspect_prompt
from backend.security.prompt_injection import inspect_prompt_injection
from backend.security.response_filter import inspect_response
from backend.services.semantic_cache import get_cached_response, cache_response
from backend.services.audit import record_audit_log
from backend.services.policy_service import get_active_policy
from backend.policy.engine import PolicyEngine
from backend.providers import get_provider, resolve_provider_name
from backend.observability.metrics import (
    record_request_metric,
    record_model_denied,
    record_pii_detected,
    record_prompt_injection,
    record_provider_metric,
    record_response_security_metric,
    record_cache_metric
)
from backend.observability.logging import log_security_event
from backend.observability.tracing import trace_span

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api",
    tags=["LLM Gateway"]
)


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    response: Response,
    x_api_key: str | None = Header(default=None),
    user: dict = Depends(authenticate_api_key)
):
    start_time = time.perf_counter()
    request_id = str(uuid.uuid4())
    response.headers["X-Request-ID"] = request_id

    username = user.get("user", "unknown")
    role = user.get("role", "unknown")
    provider_name = resolve_provider_name(model=request.model)

    # 1. Load Active Security Policy (Hierarchical: Redis -> Postgres -> Built-in Default)
    policy = await get_active_policy()
    policy_version = policy.policy_version

    with trace_span("gateway.request", {
        "request_id": request_id,
        "user": username,
        "role": role,
        "model": request.model,
        "provider": provider_name,
        "policy_version": policy_version
    }):
        with trace_span("security.policy", {
            "policy_version": policy_version,
            "decision": "ACTIVE_POLICY_LOADED"
        }):
            pass

        # 2. RBAC Model Authorization - Verify if user's role is allowed to access target model
        with trace_span("security.rbac", {"role": role, "model": request.model, "policy_version": policy_version}):
            if not is_model_allowed(role, request.model, policy=policy):
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                duration_s = time.perf_counter() - start_time
                
                record_model_denied(role=role)
                record_request_metric(method="POST", route="/api/chat", status=403, action="BLOCK", duration_s=duration_s)
                
                log_security_event(
                    event_type="MODEL_ACCESS_DENIED",
                    request_id=request_id,
                    action="BLOCK",
                    response_status=403,
                    user=username,
                    role=role,
                    model=request.model,
                    provider=provider_name,
                    threat_type="MODEL_ACCESS_DENIED",
                    risk_score=75,
                    latency_ms=latency_ms
                )

                await record_audit_log(
                    request_id=request_id,
                    user=username,
                    role=role,
                    model=request.model,
                    action="BLOCK",
                    risk_score=75,
                    pii_detected=False,
                    injection_detected=False,
                    threat_type="MODEL_ACCESS_DENIED",
                    response_status=403,
                    latency_ms=latency_ms,
                    detected_entities=[],
                    cache_hit=False,
                    provider=provider_name,
                    policy_version=policy_version
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "request_id": request_id,
                        "message": "You are not authorized to use this model",
                        "threat_type": "MODEL_ACCESS_DENIED",
                        "action": "BLOCK",
                        "policy_version": policy_version
                    },
                    headers={"X-Request-ID": request_id}
                )

        # 3. Rate Limiting based on active policy configuration
        req_limit, win_sec = PolicyEngine.get_rate_limit(policy)
        await check_rate_limit(x_api_key, role=role, limit=req_limit, window_seconds=win_sec)

        # 4. Input DLP & Presidio PII Inspection (masks PII -> sanitized prompt)
        with trace_span("security.input_dlp"):
            dlp_result = inspect_prompt(request.prompt)
            if dlp_result.pii_detected:
                record_pii_detected(dlp_result.detected_entities)

        # 5. Prompt Injection & Jailbreak Detection evaluated against policy block_threshold
        with trace_span("security.prompt_injection"):
            injection_result = inspect_prompt_injection(
                dlp_result.sanitized_prompt,
                block_threshold=policy.input_security.block_threshold
            )

        # Compute overall input risk score
        input_risk_score = max(dlp_result.risk_score, injection_result.risk_score)

        # 6. Security Policy Decision - Block if prompt injection detected with HIGH/CRITICAL risk
        if injection_result.action == "BLOCK":
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            duration_s = time.perf_counter() - start_time
            threat = injection_result.threat_type or "PROMPT_INJECTION"

            record_prompt_injection(threat_type=threat, role=role)
            record_request_metric(method="POST", route="/api/chat", status=403, action="BLOCK", duration_s=duration_s)

            log_security_event(
                event_type="PROMPT_INJECTION",
                request_id=request_id,
                action="BLOCK",
                response_status=403,
                user=username,
                role=role,
                model=request.model,
                provider=provider_name,
                threat_type=threat,
                risk_score=input_risk_score,
                pii_detected=dlp_result.pii_detected,
                injection_detected=True,
                latency_ms=latency_ms,
                detected_entities=dlp_result.detected_entities
            )

            # Record audit log for blocked injection (Strict privacy: metadata only)
            await record_audit_log(
                request_id=request_id,
                user=username,
                role=role,
                model=request.model,
                action="BLOCK",
                risk_score=input_risk_score,
                pii_detected=dlp_result.pii_detected,
                injection_detected=True,
                threat_type=threat,
                response_status=403,
                latency_ms=latency_ms,
                detected_entities=dlp_result.detected_entities,
                cache_hit=False,
                provider=provider_name,
                policy_version=policy_version
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "request_id": request_id,
                    "message": "Request blocked by AI security policy",
                    "threat_type": threat,
                    "risk_score": input_risk_score,
                    "action": "BLOCK",
                    "policy_version": policy_version
                },
                headers={"X-Request-ID": request_id}
            )

        # 7. Semantic Cache Lookup (Operates on sanitized prompt, isolated by model, role, and provider)
        cached_response = None
        if PolicyEngine.is_cache_enabled(policy):
            with trace_span("cache.lookup", {"provider": provider_name, "model": request.model}):
                cached_response = await get_cached_response(
                    prompt=dlp_result.sanitized_prompt,
                    model=request.model,
                    user_role=role,
                    provider=provider_name
                )

        final_input_action = dlp_result.action if dlp_result.pii_detected else "ALLOW"

        if cached_response is not None:
            # Cache HIT: Return immediately without invoking upstream LLM
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            duration_s = time.perf_counter() - start_time

            record_cache_metric(provider=provider_name, hit=True)
            record_request_metric(method="POST", route="/api/chat", status=200, action=final_input_action, duration_s=duration_s)

            log_security_event(
                event_type="CACHE_HIT",
                request_id=request_id,
                action=final_input_action,
                response_status=200,
                user=username,
                role=role,
                model=request.model,
                provider=provider_name,
                risk_score=input_risk_score,
                pii_detected=dlp_result.pii_detected,
                injection_detected=False,
                latency_ms=latency_ms,
                cache_hit=True,
                detected_entities=dlp_result.detected_entities
            )

            with trace_span("audit.persist"):
                await record_audit_log(
                    request_id=request_id,
                    user=username,
                    role=role,
                    model=request.model,
                    action=final_input_action,
                    risk_score=input_risk_score,
                    pii_detected=dlp_result.pii_detected,
                    injection_detected=False,
                    threat_type=None,
                    response_status=200,
                    latency_ms=latency_ms,
                    detected_entities=dlp_result.detected_entities,
                    response_risk_score=0,
                    response_action="ALLOW",
                    response_threat_type=None,
                    cache_hit=True,
                    provider=provider_name,
                    policy_version=policy_version
                )

            return ChatResponse(
                request_id=request_id,
                response=cached_response,
                model=request.model,
                status="success",
                security=SecurityInfo(
                    pii_detected=dlp_result.pii_detected,
                    injection_detected=False,
                    risk_score=input_risk_score,
                    action=final_input_action,
                    detected_entities=dlp_result.detected_entities,
                    threat_type=None,
                    response_risk_score=0,
                    response_action="ALLOW",
                    response_threat_type=None,
                    cache_hit=True
                )
            )

        # 8. Cache MISS: Resolve Provider & Generate Completion (Provider receives ONLY sanitized prompt)
        record_cache_metric(provider=provider_name, hit=False)
        provider = get_provider(model=request.model)
        prov_start = time.perf_counter()

        with trace_span("provider.generate", {"provider": provider_name, "model": request.model}):
            try:
                raw_llm_response = await provider.generate(
                    prompt=dlp_result.sanitized_prompt,
                    model=request.model
                )
                prov_duration = time.perf_counter() - prov_start
                record_provider_metric(provider=provider_name, model=request.model, status="success", duration_s=prov_duration)
            except HTTPException as http_exc:
                prov_duration = time.perf_counter() - prov_start
                record_provider_metric(provider=provider_name, model=request.model, status="error", duration_s=prov_duration, is_error=True)
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                duration_s = time.perf_counter() - start_time

                record_request_metric(method="POST", route="/api/chat", status=http_exc.status_code, action="ERROR", duration_s=duration_s)

                log_security_event(
                    event_type="PROVIDER_ERROR",
                    request_id=request_id,
                    action="ERROR",
                    response_status=http_exc.status_code,
                    user=username,
                    role=role,
                    model=request.model,
                    provider=provider_name,
                    risk_score=input_risk_score,
                    latency_ms=latency_ms
                )

                with trace_span("audit.persist"):
                    await record_audit_log(
                        request_id=request_id,
                        user=username,
                        role=role,
                        model=request.model,
                        action="ERROR",
                        risk_score=input_risk_score,
                        pii_detected=dlp_result.pii_detected,
                        injection_detected=injection_result.detected,
                        threat_type=injection_result.threat_type,
                        response_status=http_exc.status_code,
                        latency_ms=latency_ms,
                        detected_entities=dlp_result.detected_entities,
                        cache_hit=False,
                        provider=provider_name,
                        policy_version=policy_version
                    )
                raise http_exc

        # 9. LLM Response Security & Output Filtering against policy thresholds
        with trace_span("security.response_filter"):
            response_filter = inspect_response(
                raw_llm_response,
                block_threshold=policy.response_security.block_threshold
            )
            if response_filter.detected_entities:
                record_pii_detected(response_filter.detected_entities)

        # Check if response violated security policy (Secret leakage or Unsafe content)
        if response_filter.action == "BLOCK":
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            duration_s = time.perf_counter() - start_time

            record_response_security_metric(action="BLOCK", threat_type=response_filter.threat_type, role=role)
            record_request_metric(method="POST", route="/api/chat", status=403, action="BLOCK", duration_s=duration_s)

            log_security_event(
                event_type=response_filter.threat_type or "RESPONSE_BLOCK",
                request_id=request_id,
                action="BLOCK",
                response_status=403,
                user=username,
                role=role,
                model=request.model,
                provider=provider_name,
                threat_type=response_filter.threat_type,
                risk_score=response_filter.risk_score,
                latency_ms=latency_ms,
                detected_entities=response_filter.detected_entities
            )

            # Blocked responses are NEVER cached
            with trace_span("audit.persist"):
                await record_audit_log(
                    request_id=request_id,
                    user=username,
                    role=role,
                    model=request.model,
                    action="BLOCK",
                    risk_score=max(input_risk_score, response_filter.risk_score),
                    pii_detected=dlp_result.pii_detected,
                    injection_detected=injection_result.detected,
                    threat_type=response_filter.threat_type,
                    response_status=403,
                    latency_ms=latency_ms,
                    detected_entities=dlp_result.detected_entities + response_filter.detected_entities,
                    response_risk_score=response_filter.risk_score,
                    response_action=response_filter.action,
                    response_threat_type=response_filter.threat_type,
                    cache_hit=False,
                    provider=provider_name,
                    policy_version=policy_version
                )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "request_id": request_id,
                    "message": "Response blocked by AI security policy",
                    "threat_type": response_filter.threat_type,
                    "risk_score": response_filter.risk_score,
                    "action": "BLOCK",
                    "policy_version": policy_version
                },
                headers={"X-Request-ID": request_id}
            )

        # 10. Cache approved sanitized response in Redis
        if PolicyEngine.is_cache_enabled(policy):
            with trace_span("cache.write", {"provider": provider_name, "model": request.model}):
                await cache_response(
                    prompt=dlp_result.sanitized_prompt,
                    model=request.model,
                    user_role=role,
                    response=response_filter.sanitized_response,
                    provider=provider_name
                )

        final_overall_action = "SANITIZE" if (dlp_result.action == "SANITIZE" or response_filter.action == "SANITIZE") else "ALLOW"

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        duration_s = time.perf_counter() - start_time

        record_request_metric(method="POST", route="/api/chat", status=200, action=final_overall_action, duration_s=duration_s)

        log_security_event(
            event_type="CHAT_SUCCESS",
            request_id=request_id,
            action=final_overall_action,
            response_status=200,
            user=username,
            role=role,
            model=request.model,
            provider=provider_name,
            risk_score=input_risk_score,
            pii_detected=dlp_result.pii_detected or bool(response_filter.detected_entities),
            injection_detected=injection_result.detected,
            latency_ms=latency_ms,
            cache_hit=False,
            detected_entities=list(set(dlp_result.detected_entities + response_filter.detected_entities))
        )

        # 11. Record audit log for allowed/sanitized request (Strict privacy: metadata only)
        with trace_span("audit.persist"):
            await record_audit_log(
                request_id=request_id,
                user=username,
                role=role,
                model=request.model,
                action=final_overall_action,
                risk_score=input_risk_score,
                pii_detected=dlp_result.pii_detected or bool(response_filter.detected_entities),
                injection_detected=injection_result.detected,
                threat_type=injection_result.threat_type,
                response_status=200,
                latency_ms=latency_ms,
                detected_entities=list(set(dlp_result.detected_entities + response_filter.detected_entities)),
                response_risk_score=response_filter.risk_score,
                response_action=response_filter.action,
                response_threat_type=response_filter.threat_type,
                cache_hit=False,
                provider=provider_name,
                policy_version=policy_version
            )

        # 12. Safe response with comprehensive security metadata, latency, request_id, and cache_hit status
        return ChatResponse(
            request_id=request_id,
            response=response_filter.sanitized_response,
            model=request.model,
            status="success",
            security=SecurityInfo(
                pii_detected=dlp_result.pii_detected or bool(response_filter.detected_entities),
                injection_detected=injection_result.detected,
                risk_score=input_risk_score,
                action=final_overall_action,
                detected_entities=list(set(dlp_result.detected_entities + response_filter.detected_entities)),
                threat_type=injection_result.threat_type,
                response_risk_score=response_filter.risk_score,
                response_action=response_filter.action,
                response_threat_type=response_filter.threat_type,
                cache_hit=False
            )
        )

