import uuid
import time
import logging
from datetime import datetime, timezone
from typing import List, Optional
import httpx

from backend.redteam.catalog import get_test_catalog
from backend.redteam.models import (
    SecurityTestCase,
    SecurityTestResult,
    SecurityTestFinding,
    SecurityReport
)
from backend.redteam.executor import execute_test_case
from backend.redteam.reporter import generate_security_report
from backend.services.policy_service import get_active_policy
from backend.observability.metrics import (
    record_security_test_metric,
    record_security_finding_metric
)
from backend.observability.logging import log_security_event
from backend.observability.tracing import trace_span
from backend.db.database import AsyncSessionLocal
from backend.db.models import (
    SecurityTestRunModel,
    SecurityTestResultModel,
    SecurityTestFindingModel
)

logger = logging.getLogger(__name__)


async def run_security_validation_suite(
    categories: Optional[List[str]] = None,
    created_by: str = "system",
    custom_client: Optional[httpx.AsyncClient] = None
) -> SecurityReport:
    """
    Orchestrate the deterministic security validation / red-team testing suite.
    - Generates unique run_id
    - Loads active security policy version
    - Executes catalog test cases with OpenTelemetry tracing
    - Records Prometheus metrics with low-cardinality labels
    - Logs normalized SIEM security events
    - Persists test run, individual results, and findings in PostgreSQL
    """
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    started_at = datetime.now(timezone.utc)

    # 1. Resolve Active Security Policy
    try:
        active_policy = await get_active_policy()
        policy_version = active_policy.policy_version
    except Exception as e:
        logger.warning(f"Could not load active policy for redteam run: {e}")
        policy_version = "1.0.0"

    # 2. Select Test Cases from Server-Controlled Catalog
    tests_to_run: List[SecurityTestCase] = get_test_catalog(categories)

    results: List[SecurityTestResult] = []
    findings: List[SecurityTestFinding] = []

    # 3. OpenTelemetry Root Span
    with trace_span("security.redteam.run", {
        "run_id": run_id,
        "policy_version": policy_version,
        "created_by": created_by,
        "total_tests": len(tests_to_run)
    }):
        # Setup AsyncClient (In-process ASGI by default if no client passed)
        if custom_client is not None:
            client = custom_client
            owns_client = False
        else:
            from backend.main import app
            client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test"
            )
            owns_client = True

        try:
            for test_case in tests_to_run:
                # Reset rate limiter counter for the test key to guarantee clean assertion environment
                if test_case.api_key_role and test_case.api_key_role in ("admin", "analyst", "developer"):
                    key_map = {"admin": "dev-key-12345", "analyst": "test-key-67890", "developer": "dev-user-key-54321"}
                    k = key_map.get(test_case.api_key_role)
                    if k:
                        try:
                            from backend.core.redis_client import redis_client
                            await redis_client.delete(f"rate_limit:{k}")
                        except Exception:
                            pass

                test_start = time.perf_counter()

                # Child Span per Test Case
                with trace_span("security.redteam.test", {
                    "run_id": run_id,
                    "test_id": test_case.test_id,
                    "category": test_case.category.value,
                    "policy_version": policy_version
                }):
                    test_result, test_finding = await execute_test_case(
                        client=client,
                        test_case=test_case,
                        run_id=run_id,
                        policy_version=policy_version
                    )

                test_duration = time.perf_counter() - test_start
                results.append(test_result)


                # Record Prometheus Metric (Low Cardinality: category, status)
                record_security_test_metric(
                    category=test_result.category,
                    status=test_result.status,
                    duration_s=test_duration
                )

                if test_finding:
                    findings.append(test_finding)
                    record_security_finding_metric(
                        category=test_finding.category,
                        severity=test_finding.severity
                    )

                    # Emit SIEM event for failed security validation control
                    sev_event = "SECURITY_TEST_CRITICAL" if test_finding.severity == "CRITICAL" else "SECURITY_TEST_FAILED"
                    log_security_event(
                        event_type=sev_event,
                        request_id=f"redteam-{test_finding.finding_id}",
                        action="BLOCK",
                        response_status=test_result.actual_status or 500,
                        user=created_by,
                        role="security-validator",
                        threat_type=test_result.threat_type or test_case.category.value,
                        risk_score=90 if test_finding.severity == "CRITICAL" else 60
                    )

        finally:
            if owns_client:
                await client.aclose()

    completed_at = datetime.now(timezone.utc)

    # 4. Generate Structured Report
    overall_status = "COMPLETED"
    if any(r.status == "ERROR" for r in results):
        overall_status = "COMPLETED_WITH_ERRORS"
    elif any(r.status == "FAIL" for r in results):
        overall_status = "COMPLETED_WITH_FAILURES"

    report = generate_security_report(
        run_id=run_id,
        status=overall_status,
        policy_version=policy_version,
        started_at=started_at,
        completed_at=completed_at,
        created_by=created_by,
        results=results,
        findings=findings
    )

    # 5. Emit SIEM event for Run Completion
    log_security_event(
        event_type="SECURITY_TEST_COMPLETED",
        request_id=f"redteam-{run_id}",
        action="ALLOW",
        response_status=200,
        user=created_by,
        role="security-validator",
        risk_score=int(100 - report.security_score)
    )

    # 6. Persist Run, Results, and Findings in PostgreSQL
    await _persist_test_run(report)

    return report


async def _persist_test_run(report: SecurityReport) -> None:
    """
    Safely persist test run records into PostgreSQL database.
    Fails safely with warning if database is unavailable.
    """
    try:
        async with AsyncSessionLocal() as session:
            # 1. Run Header
            run_model = SecurityTestRunModel(
                run_id=report.run_id,
                started_at=report.started_at,
                completed_at=report.completed_at,
                status=report.status,
                total_tests=report.summary.get("total_tests", 0),
                passed_tests=report.summary.get("passed_tests", 0),
                failed_tests=report.summary.get("failed_tests", 0),
                error_tests=report.summary.get("error_tests", 0),
                skipped_tests=report.summary.get("skipped_tests", 0),
                security_score=report.security_score,
                created_by=report.created_by,
                policy_version=report.policy_version
            )
            session.add(run_model)

            # 2. Individual Test Results
            for r in report.test_results:
                res_model = SecurityTestResultModel(
                    run_id=r.run_id,
                    test_id=r.test_id,
                    category=r.category,
                    status=r.status,
                    severity=r.severity,
                    expected_action=r.expected_action,
                    actual_action=r.actual_action,
                    expected_status=r.expected_status,
                    actual_status=r.actual_status,
                    threat_type=r.threat_type,
                    latency_ms=r.latency_ms,
                    policy_version=r.policy_version,
                    error_message=r.error_message,
                    created_at=r.created_at
                )
                session.add(res_model)

            # 3. Security Findings
            for f in report.findings:
                find_model = SecurityTestFindingModel(
                    finding_id=f.finding_id,
                    run_id=f.run_id,
                    test_id=f.test_id,
                    category=f.category,
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    expected_behavior=f.expected_behavior,
                    actual_behavior=f.actual_behavior,
                    endpoint=f.endpoint,
                    policy_version=f.policy_version,
                    created_at=f.created_at
                )
                session.add(find_model)

            await session.commit()
            logger.info(f"Persisted security test run {report.run_id} successfully in database.")
    except Exception as exc:
        logger.warning(f"Failed to persist security test run to database ({exc}), continuing safely.")
