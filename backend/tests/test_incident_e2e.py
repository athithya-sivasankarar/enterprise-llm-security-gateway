import pytest
from datetime import datetime, timezone
from backend.db.database import AsyncSessionLocal
from backend.db.models import SecurityIncidentModel, SecurityAlertModel, SecurityReportModel
from backend.services.incident_service import (
    create_incident,
    get_incident_detail,
    add_incident_note,
    attach_evidence,
    attach_report,
    record_response_action,
    change_incident_status,
    correlate_alert_safe
)
from backend.alerts.engine import _create_and_persist_alert
from backend.services.report_service import create_report
from backend.reporting.models import ReportCreateRequest, ReportType


@pytest.mark.asyncio
async def test_full_e2e_security_incident_workflow():
    """
    End-to-end integration test:
    Security Test / Campaign -> Alert Trigger -> Incident Correlation ->
    Timeline -> Evidence -> Report Link -> Analyst Investigation ->
    Controlled Response -> Resolution -> Audit Trail.
    """
    async with AsyncSessionLocal() as session:
        # Step 1: Simulate Campaign alert generation (Step 16/17)
        now = datetime.now(timezone.utc)
        camp_id = f"camp-e2e-{int(now.timestamp())}"
        crun_id = f"crun-e2e-{int(now.timestamp())}"

        alert = await _create_and_persist_alert(
            db=session,
            campaign_id=camp_id,
            campaign_run_id=crun_id,
            alert_type="CAMPAIGN_REGRESSION",
            severity="CRITICAL",
            title="E2E Critical Regression in Prompt Injection Filter",
            description="Automated red-team run detected 2 bypass regressions",
            score=68.0,
            baseline_score=92.0,
            score_delta=-24.0,
            regression_count=2,
            policy_version="1.0.0",
            created_at=now
        )

        assert alert is not None
        assert alert.alert_id.startswith("alert-")

        # Step 2: Verify automatic fail-safe correlation into an Incident (Step 19)
        from sqlalchemy import select
        stmt_inc = select(SecurityIncidentModel).where(
            SecurityIncidentModel.source_alert_id == alert.alert_id
        )
        res_inc = await session.execute(stmt_inc)
        inc = res_inc.scalar_one_or_none()
        assert inc is not None
        assert inc.severity in ("CRITICAL", "HIGH")
        assert inc.status == "OPEN"
        assert inc.risk_score >= 60

        incident_id = inc.incident_id

        # Step 3: SOC Analyst attaches investigation note
        note = await add_incident_note(
            session,
            incident_id=incident_id,
            note_text="Investigating bypass attempt on endpoint /api/chat. Redacting any customer references.",
            author="soc-lead-analyst"
        )
        assert note.note_id.startswith("note-")

        # Step 4: Attach Evidence Artifact
        evidence = await attach_evidence(
            session,
            incident_id=incident_id,
            evidence_type="SECURITY_TEST_RESULT",
            description="Normalized failure payload metadata for prompt injection test",
            source_id="test-pi-001",
            user="soc-lead-analyst"
        )
        assert evidence.sha256_hash is not None
        assert len(evidence.sha256_hash) == 64

        # Step 5: Generate Step 18 Executive Compliance Report and link to incident
        rep = await create_report(
            session,
            ReportCreateRequest(
                report_type=ReportType.EXECUTIVE.value,
                title="E2E Incident Posture & Compliance Report",
                description="Auditable security compliance report generated during incident response"
            ),
            user="soc-lead-analyst"
        )
        assert rep.report_id.startswith("rep-")

        rep_evidence = await attach_report(
            session,
            incident_id=incident_id,
            report_id=rep.report_id,
            user="soc-lead-analyst"
        )
        assert rep_evidence.evidence_type == "REPORT"

        # Step 6: Record Controlled Response Actions
        action = await record_response_action(
            session,
            incident_id=incident_id,
            action_type="REQUEST_POLICY_REVIEW",
            description="Requesting prompt injection threshold tightening in policy v1.1.0",
            requested_by="soc-lead-analyst",
            approved_by="sec-admin"
        )
        assert action.action_type == "REQUEST_POLICY_REVIEW"
        assert action.status == "COMPLETED"

        # Step 7: Resolve Incident
        resolved = await change_incident_status(
            session,
            incident_id=incident_id,
            new_status="RESOLVED",
            user="sec-admin",
            reason="Policy updated with tightened jailbreak heuristics"
        )
        assert resolved.status == "RESOLVED"
        assert resolved.resolved_at is not None

        # Step 8: Verify Complete Investigation Detail Bundle
        detail = await get_incident_detail(session, incident_id)
        assert detail.incident.status == "RESOLVED"
        assert len(detail.timeline) >= 4
        assert len(detail.evidence) >= 2
        assert len(detail.notes) >= 1
        assert len(detail.actions) >= 1
