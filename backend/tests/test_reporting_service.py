import pytest
import uuid
from datetime import datetime, timezone
from backend.db.database import AsyncSessionLocal
from backend.campaign.models import CampaignCreateRequest
from backend.services.campaign_service import create_campaign, execute_campaign
from backend.reporting.models import ReportCreateRequest
from backend.services.report_service import (
    create_report,
    get_report,
    list_reports,
    get_report_evidence,
    export_report,
    verify_report_integrity_service,
    delete_report
)


@pytest.mark.asyncio
async def test_reporting_service_lifecycle_from_campaign():
    async with AsyncSessionLocal() as session:
        # 1. Create and Execute Campaign
        camp_req = CampaignCreateRequest(
            name=f"Report Service Campaign {uuid.uuid4().hex[:6]}",
            category_filter=["AUTHENTICATION", "INPUT_DLP"]
        )
        camp = await create_campaign(session, camp_req, user="service-tester")
        run_sum, comp = await execute_campaign(session, camp.campaign_id, user="service-tester")

        # 2. Create Report
        rep_req = ReportCreateRequest(
            report_type="CAMPAIGN",
            title="Automated Assessment Report",
            campaign_id=camp.campaign_id,
            campaign_run_id=run_sum.campaign_run_id
        )
        report_summary = await create_report(session, rep_req, user="service-tester")
        assert report_summary.report_id.startswith("rep-")
        assert report_summary.status == "COMPLETED"
        assert report_summary.report_hash is not None

        # 3. Get Report Document
        full_report = await get_report(session, report_summary.report_id)
        assert full_report.report_id == report_summary.report_id
        assert len(full_report.compliance_mappings) > 0

        # 4. List Reports
        reports_list = await list_reports(session, report_type="CAMPAIGN")
        assert any(r.report_id == report_summary.report_id for r in reports_list)

        # 5. Get Evidence
        evidence = await get_report_evidence(session, report_summary.report_id)
        assert len(evidence) > 0

        # 6. Export Formats
        json_content, j_type, _ = await export_report(session, report_summary.report_id, "json")
        assert "application/json" in j_type

        md_content, m_type, _ = await export_report(session, report_summary.report_id, "markdown")
        assert "markdown" in m_type

        csv_content, c_type, _ = await export_report(session, report_summary.report_id, "csv")
        assert "csv" in c_type

        pdf_bytes, p_type, _ = await export_report(session, report_summary.report_id, "pdf")
        assert "application/pdf" in p_type
        assert pdf_bytes.startswith(b"%PDF-")

        # 7. Verify Integrity
        verify_res = await verify_report_integrity_service(session, report_summary.report_id)
        assert verify_res["valid"] is True

        # 8. Delete Report
        del_res = await delete_report(session, report_summary.report_id, user="service-tester")
        assert del_res["status"] == "deleted"
