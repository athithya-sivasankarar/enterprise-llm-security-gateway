import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, cast
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc

from backend.db.models import (
    SecurityControlAssuranceModel,
    SecurityControlModel,
    SecurityTestResultModel,
    SecurityRegressionModel,
    SecurityIncidentModel,
    SecurityExposureModel,
    SecurityAssetFindingModel,
    SecurityGovernanceEventModel
)
from backend.governance.models import ControlAssurance
from backend.governance.sanitizer import sanitize_governance_metadata

logger = logging.getLogger(__name__)

# Standard 14 core security control domains mapped to their default names
CORE_SECURITY_CONTROLS = {
    "AUTHENTICATION": ("API Key & Identity Authentication", "PREVENTIVE"),
    "RBAC": ("Role-Based Model Access Control", "PREVENTIVE"),
    "INPUT_DLP": ("Input Sensitive Data Loss Prevention", "PREVENTIVE"),
    "PROMPT_INJECTION": ("Direct & Indirect Prompt Injection Detection", "PREVENTIVE"),
    "JAILBREAK": ("Multi-Turn Jailbreak & Safety Guardrail Protection", "PREVENTIVE"),
    "SYSTEM_PROMPT_EXTRACTION": ("System Prompt & Guardrail Extraction Prevention", "PREVENTIVE"),
    "SECRET_LEAKAGE": ("Credential & API Secret Exfiltration Prevention", "PREVENTIVE"),
    "UNSAFE_CONTENT": ("Malicious & Dangerous Content Moderation", "PREVENTIVE"),
    "RESPONSE_PII": ("Response PII & Sensitive Entity Masking", "CORRECTIVE"),
    "RATE_LIMITING": ("Adaptive Token & Request Rate Limiting", "PREVENTIVE"),
    "CACHE_ISOLATION": ("Semantic Cache Tenant & Isolation Control", "PREVENTIVE"),
    "POLICY": ("Centralized Policy Validation & Enforcement", "PREVENTIVE"),
    "AUDIT": ("Immutable Security Audit Trail & Integrity", "DETECTIVE"),
    "OBSERVABILITY": ("Real-Time Telemetry & Metric Instrumentation", "DETECTIVE")
}


async def evaluate_control_assurance(
    db: AsyncSession,
    control_id: Optional[str] = None,
    actor: str = "system"
) -> List[ControlAssurance]:
    """
    Evaluate continuous control assurance by analyzing actual persisted security test results,
    campaign regressions, active exposures, open incidents, and asset findings.
    Persists updated records into security_control_assurance.
    """
    now = datetime.now(timezone.utc)
    controls_to_eval = [control_id.upper()] if control_id and control_id.upper() in CORE_SECURITY_CONTROLS else list(CORE_SECURITY_CONTROLS.keys())

    # 1. Fetch latest test results per category
    res_tests = await db.execute(select(SecurityTestResultModel).order_by(desc(SecurityTestResultModel.created_at)).limit(1000))
    test_results = res_tests.scalars().all()

    # 2. Fetch active regressions
    res_reg = await db.execute(select(SecurityRegressionModel).order_by(desc(SecurityRegressionModel.created_at)).limit(100))
    regressions = res_reg.scalars().all()

    # 3. Fetch open incidents
    res_inc = await db.execute(select(SecurityIncidentModel).where(SecurityIncidentModel.status.in_(["OPEN", "INVESTIGATING", "CONTAINED"])))
    open_incidents = res_inc.scalars().all()

    # 4. Fetch open exposures
    res_exp = await db.execute(select(SecurityExposureModel).where(SecurityExposureModel.status == "OPEN"))
    open_exposures = res_exp.scalars().all()

    # 5. Fetch open findings
    res_find = await db.execute(select(SecurityAssetFindingModel).where(SecurityAssetFindingModel.status == "OPEN"))
    open_findings = res_find.scalars().all()

    assurance_list: List[ControlAssurance] = []

    for ctrl in controls_to_eval:
        ctrl_name, ctrl_type = CORE_SECURITY_CONTROLS.get(ctrl, (ctrl, "PREVENTIVE"))

        # Aggregate test stats
        ctrl_tests = [t for t in test_results if (t.category or "").upper() == ctrl]
        test_count = len(ctrl_tests)
        passed_tests = len([t for t in ctrl_tests if t.status == "PASS"])
        failed_tests = len([t for t in ctrl_tests if t.status == "FAIL"])
        last_tested_at = ctrl_tests[0].created_at if ctrl_tests else None

        coverage_pct = round((passed_tests / test_count * 100.0), 1) if test_count > 0 else 100.0

        # Regressions in domain
        ctrl_regs = [r for r in regressions if (r.category or "").upper() == ctrl]
        reg_count = len(ctrl_regs)

        # Incidents in domain
        ctrl_incs = [i for i in open_incidents if (getattr(i, 'incident_type', '') or '').upper() == ctrl or ctrl in (getattr(i, 'title', '') or '').upper()]
        inc_count = len(ctrl_incs)

        # Exposures in domain
        ctrl_exps = [e for e in open_exposures if (e.category or "").upper() == ctrl]
        exp_count = len(ctrl_exps)

        # Findings in domain
        ctrl_finds = [f for f in open_findings if (f.category or "").upper() == ctrl]
        find_count = len(ctrl_finds)

        # Deterministic Effectiveness Score Calculation (0-100)
        # Deduct penalties for failures, regressions, incidents, exposures, and findings
        penalties = (failed_tests * 20) + (reg_count * 15) + (inc_count * 15) + (exp_count * 10) + (find_count * 5)
        effectiveness_score = max(0.0, min(100.0, 100.0 - penalties))
        risk_score = int(100.0 - effectiveness_score)

        gap_count = 1 if (failed_tests > 0 or coverage_pct < 80.0 or exp_count > 0 or find_count > 0) else 0

        if effectiveness_score >= 90.0 and gap_count == 0:
            last_status = "PASS"
        elif effectiveness_score >= 60.0:
            last_status = "DEGRADED"
        else:
            last_status = "GAP"

        # Check existing db model
        res_db = await db.execute(select(SecurityControlAssuranceModel).where(SecurityControlAssuranceModel.control_id == ctrl).order_by(desc(SecurityControlAssuranceModel.created_at)))
        model = res_db.scalars().first()

        resolved_tested_at: Optional[datetime] = last_tested_at or (cast(Optional[datetime], model.last_tested_at) if model else None)

        if model:
            model.test_count = test_count
            model.passed_tests = passed_tests
            model.failed_tests = failed_tests
            model.coverage_percentage = coverage_pct
            model.effectiveness_score = effectiveness_score
            model.gap_count = gap_count
            model.regression_count = reg_count
            model.last_tested_at = resolved_tested_at
            model.last_status = last_status
            model.risk_score = risk_score
            model.updated_at = now
        else:
            assurance_id = f"ASR-{ctrl}-{uuid.uuid4().hex[:6].upper()}"
            model = SecurityControlAssuranceModel(
                assurance_id=assurance_id,
                control_id=ctrl,
                assessment_period="current",
                test_count=test_count,
                passed_tests=passed_tests,
                failed_tests=failed_tests,
                coverage_percentage=coverage_pct,
                effectiveness_score=effectiveness_score,
                gap_count=gap_count,
                regression_count=reg_count,
                last_tested_at=resolved_tested_at or now,
                last_status=last_status,
                risk_score=risk_score,
                policy_version="1.0.0",
                created_at=now,
                updated_at=now
            )
            db.add(model)

        assurance_list.append(ControlAssurance(
            assurance_id=str(model.assurance_id),
            control_id=ctrl,
            name=ctrl_name,
            domain=ctrl,
            control_type=ctrl_type,
            assessment_period="current",
            test_count=test_count,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            coverage_percentage=coverage_pct,
            effectiveness_score=effectiveness_score,
            gap_count=gap_count,
            regression_count=reg_count,
            open_findings=find_count,
            open_incidents=inc_count,
            open_exposures=exp_count,
            last_tested_at=resolved_tested_at or (cast(Optional[datetime], model.last_tested_at) if model else None),
            last_status=last_status,
            risk_score=risk_score,
            policy_version=str(model.policy_version or "1.0.0")
        ))

    event = SecurityGovernanceEventModel(
        event_id=f"GEVT-{uuid.uuid4().hex[:8].upper()}",
        event_type="SECURITY_CONTROL_ASSURANCE_UPDATED",
        entity_type="ASSURANCE",
        entity_id=control_id or "ALL_CONTROLS",
        actor=actor,
        description=f"Evaluated continuous control assurance across {len(assurance_list)} security controls",
        metadata_json=sanitize_governance_metadata({"evaluated_controls_count": len(assurance_list)}),
        created_at=now
    )
    db.add(event)
    await db.commit()

    return assurance_list


async def get_control_assurance(
    db: AsyncSession,
    control_id: Optional[str] = None
) -> List[ControlAssurance]:
    """
    Retrieve persisted control assurance data. If no records exist, triggers an evaluation.
    Deduplicates to return the latest record per control_id.
    """
    query = select(SecurityControlAssuranceModel).order_by(desc(SecurityControlAssuranceModel.created_at))
    if control_id:
        query = query.where(SecurityControlAssuranceModel.control_id == control_id.upper())

    res = await db.execute(query)
    models = res.scalars().all()

    if not models:
        return await evaluate_control_assurance(db, control_id=control_id)

    seen_controls = set()
    out: List[ControlAssurance] = []
    for m in models:
        if (not control_id and m.control_id not in CORE_SECURITY_CONTROLS) or m.control_id in seen_controls:
            continue
        seen_controls.add(m.control_id)
        ctrl_name, ctrl_type = CORE_SECURITY_CONTROLS.get(m.control_id, (m.control_id, "PREVENTIVE"))
        out.append(ControlAssurance(
            assurance_id=str(m.assurance_id),
            control_id=str(m.control_id),
            name=ctrl_name,
            domain=str(m.control_id),
            control_type=ctrl_type,
            assessment_period=str(m.assessment_period),
            test_count=m.test_count,
            passed_tests=m.passed_tests,
            failed_tests=m.failed_tests,
            coverage_percentage=m.coverage_percentage,
            effectiveness_score=m.effectiveness_score,
            gap_count=m.gap_count,
            regression_count=m.regression_count,
            last_tested_at=cast(Optional[datetime], m.last_tested_at),
            last_status=str(m.last_status),
            risk_score=m.risk_score,
            policy_version=str(m.policy_version or "1.0.0")
        ))
    return out
