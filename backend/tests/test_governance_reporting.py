import pytest
from backend.db.database import AsyncSessionLocal
from backend.reporting.models import ReportCreateRequest, ReportType
from backend.services.report_service import create_report, get_report, export_report


@pytest.mark.asyncio
async def test_governance_report_generation_and_exports():
    async with AsyncSessionLocal() as session:
        # 1. Generate GOVERNANCE report
        req = ReportCreateRequest(
            report_type=ReportType.GOVERNANCE.value,
            title="Enterprise Governance & Risk Assurance Report",
            description="Automated governance and continuous control assurance report"
        )
        summary = await create_report(session, req, user="chief-security-officer")
        assert summary.report_id.startswith("rep-")
        assert summary.report_type == ReportType.GOVERNANCE.value

        # 2. Get Report Detail
        detail = await get_report(session, summary.report_id)
        assert detail.report_id == summary.report_id
        assert detail.executive_summary is not None
        assert detail.report_hash is not None

        # 3. Export in all supported formats
        # JSON
        json_content, mime_json, filename_json = await export_report(session, summary.report_id, export_format="json")
        assert "application/json" in mime_json
        assert summary.report_id in str(json_content)

        # Markdown
        md_content, mime_md, filename_md = await export_report(session, summary.report_id, export_format="markdown")
        assert "text/markdown" in mime_md
        assert len(md_content) > 0

        # CSV
        csv_content, mime_csv, filename_csv = await export_report(session, summary.report_id, export_format="csv")
        assert "text/csv" in mime_csv
        assert len(csv_content) > 0

        # PDF
        pdf_content, mime_pdf, filename_pdf = await export_report(session, summary.report_id, export_format="pdf")
        assert "application/pdf" in mime_pdf
        assert len(pdf_content) > 0
