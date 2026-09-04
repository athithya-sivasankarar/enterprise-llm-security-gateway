import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from backend.db.models import (
    SecurityTestResultModel,
    SecurityRegressionModel,
    SecurityControlModel
)
from backend.control_coverage.models import (
    ControlCoverageMatrixItem,
    ControlGapItem,
    ControlCoverageSummary,
    ControlDomain,
    ControlStatus,
    ControlGapType
)

logger = logging.getLogger(__name__)

# Standard Control Inventory Definition mapped to Step 15 Tests
STANDARD_SECURITY_CONTROLS: List[Dict[str, Any]] = [
    {
        "control_id": "CTRL-AUTH-01",
        "domain": "AUTHENTICATION",
        "name": "API Key Authentication & Header Verification",
        "description": "Enforce valid X-API-Key credentials before gateway routing or caching.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["AUTH-001", "AUTH-002", "AUTH-003"]
    },
    {
        "control_id": "CTRL-RBAC-01",
        "domain": "RBAC",
        "name": "Role-Based Model Access & Dashboard Authorization",
        "description": "Authorize model execution and SOC dashboard visibility based on caller role.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["RBAC-001", "RBAC-002", "RBAC-003", "RBAC-004", "RBAC-005"]
    },
    {
        "control_id": "CTRL-RL-01",
        "domain": "RATE_LIMITING",
        "name": "Redis Distributed Rate Limiting & DoS Protection",
        "description": "Enforce per-role sliding window request limits with HTTP 429 backpressure.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["RL-001"]
    },
    {
        "control_id": "CTRL-DLP-01",
        "domain": "INPUT_DLP",
        "name": "Presidio Input PII Inspection & Data Loss Prevention",
        "description": "Scrub credit cards, SSNs, phone numbers, and emails from prompt payloads.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["DLP-001", "DLP-002", "DLP-003", "DLP-004"]
    },
    {
        "control_id": "CTRL-PI-01",
        "domain": "PROMPT_INJECTION",
        "name": "Prompt Injection & Instruction Override Guard",
        "description": "Detect and block direct adversarial overrides and heuristic delimiter injection.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["PI-001", "PI-002"]
    },
    {
        "control_id": "CTRL-JB-01",
        "domain": "JAILBREAK",
        "name": "Adversarial Persona & Jailbreak Defense",
        "description": "Block multi-turn jailbreak attempts, hypothetical roleplay, and DAN vectors.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["JB-001", "JB-002"]
    },
    {
        "control_id": "CTRL-SPE-01",
        "domain": "SYSTEM_PROMPT_EXTRACTION",
        "name": "System Prompt & Internal Meta-Instruction Protection",
        "description": "Block attempts to exfiltrate base system instructions and confidential prompts.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["SPE-001", "SPE-002"]
    },
    {
        "control_id": "CTRL-SL-01",
        "domain": "SECRET_LEAKAGE",
        "name": "Output Secret & API Key Leakage Redaction",
        "description": "Detect and block model responses leaking AWS keys, API keys, or database credentials.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["SL-001"]
    },
    {
        "control_id": "CTRL-UC-01",
        "domain": "UNSAFE_CONTENT",
        "name": "Malicious Code & Unsafe Content Filtering",
        "description": "Block malware execution payloads and harmful instructions in LLM outputs.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["UC-001"]
    },
    {
        "control_id": "CTRL-RPII-01",
        "domain": "RESPONSE_PII",
        "name": "Output PII & Customer Data Redaction Filter",
        "description": "Scrub sensitive personal data from upstream LLM completions before client return.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["RPII-001"]
    },
    {
        "control_id": "CTRL-CACHE-01",
        "domain": "CACHE_ISOLATION",
        "name": "Redis Semantic Cache Isolation & Poisoning Defense",
        "description": "Ensure cache lookup occurs only after security validation and prevents cross-tenant leaks.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["CACHE-001"]
    },
    {
        "control_id": "CTRL-POL-01",
        "domain": "POLICY",
        "name": "Centralized Dynamic Security Policy Enforcement",
        "description": "Guarantee dynamic versioned policy enforcement without service restarts.",
        "control_type": "PREVENTIVE",
        "tests_mapped": ["POL-001"]
    },
    {
        "control_id": "CTRL-AUDIT-01",
        "domain": "AUDIT",
        "name": "Immutable PostgreSQL Security Audit Trail",
        "description": "Persist sanitized metadata-only audit records for all gateway transactions.",
        "control_type": "DETECTIVE",
        "tests_mapped": ["AUDIT-001"]
    },
    {
        "control_id": "CTRL-OBS-01",
        "domain": "OBSERVABILITY",
        "name": "Real-Time Prometheus & Structured SIEM Telemetry",
        "description": "Emit low-cardinality metrics and normalized JSON SIEM events for SOC monitoring.",
        "control_type": "DETECTIVE",
        "tests_mapped": ["OBS-001"]
    }
]


async def evaluate_security_control_coverage(
    db: AsyncSession,
    run_id: Optional[str] = None
) -> ControlCoverageSummary:
    """
    Deterministically evaluate security control coverage, pass rates, and gaps
    from actual persisted security test results and active regressions.
    """
    matrix: List[ControlCoverageMatrixItem] = []
    gaps: List[ControlGapItem] = []

    # Fetch latest test results
    results_map: Dict[str, Dict[str, Any]] = {}
    if run_id:
        stmt_res = select(SecurityTestResultModel).where(SecurityTestResultModel.run_id == run_id)
        res = await db.execute(stmt_res)
        for r in res.scalars().all():
            results_map[r.test_id] = {
                "status": r.status,
                "severity": r.severity,
                "created_at": r.created_at
            }
    else:
        # Fetch most recent result for each test_id
        stmt_all = select(SecurityTestResultModel).order_by(desc(SecurityTestResultModel.created_at)).limit(300)
        res_all = await db.execute(stmt_all)
        for r in res_all.scalars().all():
            if r.test_id not in results_map:
                results_map[r.test_id] = {
                    "status": r.status,
                    "severity": r.severity,
                    "created_at": r.created_at
                }

    # Fetch active regressions
    if run_id:
        stmt_reg = select(SecurityRegressionModel).where(
            (SecurityRegressionModel.campaign_run_id == run_id) | (SecurityRegressionModel.current_run_id == run_id)
        )
    else:
        stmt_reg = select(SecurityRegressionModel).order_by(desc(SecurityRegressionModel.created_at)).limit(100)
    res_reg = await db.execute(stmt_reg)
    active_regressions = {r.test_id: r for r in res_reg.scalars().all()}

    tested_count = 0
    passing_count = 0
    failing_count = 0
    regression_count = 0
    disabled_count = 0

    for ctrl in STANDARD_SECURITY_CONTROLS:
        mapped_tests = ctrl["tests_mapped"]
        executed_tests = 0
        passed_tests = 0
        has_fail = False
        has_regression = False
        latest_tested_at: Optional[datetime] = None

        for tid in mapped_tests:
            if tid in results_map:
                executed_tests += 1
                t_stat = results_map[tid]["status"].upper()
                t_date = results_map[tid]["created_at"]
                if not latest_tested_at or (t_date and t_date > latest_tested_at):
                    latest_tested_at = t_date

                if t_stat == "PASS":
                    passed_tests += 1
                else:
                    has_fail = True

            if tid in active_regressions:
                has_regression = True

        cov_pct = (executed_tests / len(mapped_tests)) * 100.0 if mapped_tests else 100.0
        pass_pct = (passed_tests / executed_tests) * 100.0 if executed_tests > 0 else 0.0

        if executed_tests == 0:
            status = ControlStatus.NOT_TESTED.value
            gaps.append(
                ControlGapItem(
                    control_id=ctrl["control_id"],
                    domain=ctrl["domain"],
                    gap_type=ControlGapType.CONTROL_NOT_TESTED.value,
                    severity="HIGH",
                    description=f"Control '{ctrl['name']}' has not been verified in any security validation run.",
                    recommendation="Schedule an automated security assessment campaign covering this domain."
                )
            )
        elif has_regression:
            status = ControlStatus.REGRESSION.value
            regression_count += 1
            tested_count += 1
            gaps.append(
                ControlGapItem(
                    control_id=ctrl["control_id"],
                    domain=ctrl["domain"],
                    gap_type=ControlGapType.CONTROL_REGRESSION.value,
                    severity="CRITICAL",
                    description=f"Security control '{ctrl['name']}' experienced an active baseline regression.",
                    recommendation="Investigate the associated regression in the SOC Incident Case Management view."
                )
            )
        elif has_fail:
            status = ControlStatus.FAIL.value
            failing_count += 1
            tested_count += 1
            gaps.append(
                ControlGapItem(
                    control_id=ctrl["control_id"],
                    domain=ctrl["domain"],
                    gap_type=ControlGapType.CONTROL_FAILING.value,
                    severity="HIGH",
                    description=f"One or more security assertions failed for control '{ctrl['name']}' ({pass_pct:.0f}% pass rate).",
                    recommendation="Review failed test findings and verify gateway filter configurations."
                )
            )
        else:
            status = ControlStatus.PASS.value
            passing_count += 1
            tested_count += 1

            if cov_pct < 100.0:
                gaps.append(
                    ControlGapItem(
                        control_id=ctrl["control_id"],
                        domain=ctrl["domain"],
                        gap_type=ControlGapType.CONTROL_PARTIALLY_COVERED.value,
                        severity="MEDIUM",
                        description=f"Control '{ctrl['name']}' is only partially tested ({executed_tests}/{len(mapped_tests)} assertions executed).",
                        recommendation="Run the complete test category suite to achieve 100% control coverage."
                    )
                )

        matrix.append(
            ControlCoverageMatrixItem(
                domain=ctrl["domain"],
                control_id=ctrl["control_id"],
                name=ctrl["name"],
                control_type=ctrl["control_type"],
                tests_mapped=mapped_tests,
                tests_executed=executed_tests,
                tests_passed=passed_tests,
                coverage_pct=cov_pct,
                pass_rate_pct=pass_pct,
                status=status,
                last_tested_at=latest_tested_at
            )
        )

    total_controls = len(STANDARD_SECURITY_CONTROLS)
    overall_coverage = (tested_count / total_controls) * 100.0 if total_controls > 0 else 0.0
    overall_pass = (passing_count / tested_count) * 100.0 if tested_count > 0 else 0.0

    return ControlCoverageSummary(
        total_controls=total_controls,
        tested_controls=tested_count,
        passing_controls=passing_count,
        failing_controls=failing_count,
        regression_controls=regression_count,
        disabled_controls=disabled_count,
        overall_coverage_pct=round(overall_coverage, 1),
        overall_pass_pct=round(overall_pass, 1),
        control_gaps_count=len(gaps),
        matrix=matrix,
        gaps=gaps
    )
