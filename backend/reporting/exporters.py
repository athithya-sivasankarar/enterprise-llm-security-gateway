import io
import csv
import json
import logging
from typing import List, Dict, Any, Optional

from backend.reporting.models import SecurityReport, EvidenceItem
from backend.reporting.sanitizer import sanitize_text

logger = logging.getLogger(__name__)


def export_json(report: SecurityReport) -> str:
    """
    Export the sanitized canonical security report as formatted JSON.
    """
    return report.model_dump_json(indent=2)


def export_markdown(report: SecurityReport) -> str:
    """
    Export the sanitized security report as standard GitHub-flavored Markdown.
    """
    es = report.executive_summary
    lines = []

    lines.append(f"# {report.title}")
    lines.append(f"**Report ID:** `{report.report_id}` | **Version:** `{report.report_version}` | **Policy:** `v{report.policy_version}`")
    lines.append(f"**Generated:** {report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')} by `{report.created_by}`")
    lines.append(f"**SHA-256 Integrity Hash:** `{report.report_hash}`")
    lines.append("")

    if report.description:
        lines.append(f"> {report.description}")
        lines.append("")

    lines.append("---")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"* **Security Score:** **{es.security_score}%** (Baseline: {es.baseline_score or 'N/A'}%, Delta: {es.score_delta or 0}%)")
    lines.append(f"* **Security Posture:** **{es.security_posture}**")
    lines.append(f"* **Total Evaluated Assertions:** {es.total_tests} (Passed: {es.passed_tests}, Failed: {es.failed_tests}, Errors: {es.error_tests}, Skipped: {es.skipped_tests})")
    lines.append(f"* **Findings Summary:** {es.critical_findings} Critical | {es.high_findings} High | {es.medium_findings} Medium | {es.low_findings} Low")
    lines.append(f"* **Regressions Detected:** {es.regression_count}")
    lines.append("")

    lines.append("---")
    lines.append("## 2. Security Control Domain Breakdown")
    lines.append("")
    lines.append("| Category / Control Domain | Tests | Passed | Failed | Score | Status |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: |")
    for cr in report.category_results:
        lines.append(f"| `{cr.category}` | {cr.total_tests} | {cr.passed_tests} | {cr.failed_tests} | **{cr.score}%** | {cr.status} |")
    lines.append("")

    if report.findings:
        lines.append("---")
        lines.append("## 3. Security Findings & Control Vulnerabilities")
        lines.append("")
        for f in report.findings:
            lines.append(f"### [{f.severity}] {f.title} (`{f.test_id}`)")
            lines.append(f"* **Category:** `{f.category}` | **Endpoint:** `{f.endpoint}`")
            lines.append(f"* **Description:** {f.description}")
            lines.append(f"* **Expected:** {f.expected_behavior}")
            lines.append(f"* **Actual:** {f.actual_behavior}")
            lines.append("")

    if report.regressions:
        lines.append("---")
        lines.append("## 4. Regression Analysis")
        lines.append("")
        for reg in report.regressions:
            lines.append(f"* **`{reg.get('test_id')}` ({reg.get('category')}):** {reg.get('description')} (Prev: `{reg.get('previous_status')}` -> Current: `{reg.get('current_status')}`)")
        lines.append("")

    lines.append("---")
    lines.append("## 5. Framework & Standards Compliance Mappings")
    lines.append("")
    lines.append(f"> **Disclaimer:** *{report.compliance_disclaimer}*")
    lines.append("")
    lines.append("| Framework | Control ID | Control Name | Mapped Gateway Controls | Evidence Items | Coverage |")
    lines.append("| :--- | :---: | :--- | :--- | :---: | :---: |")
    for cm in report.compliance_mappings:
        controls_str = ", ".join(cm.gateway_controls)
        lines.append(f"| {cm.framework} | `{cm.control_id}` | {cm.control_name} | {controls_str} | {cm.evidence_count} | {cm.coverage_status} |")
    lines.append("")

    lines.append("---")
    lines.append("## 6. Assessment Methodology & Scope Limitations")
    lines.append(f"* **Methodology:** {report.methodology}")
    lines.append(f"* **Limitations:** {report.limitations}")

    return "\n".join(lines)


def export_csv(report: SecurityReport, evidence_items: Optional[List[EvidenceItem]] = None) -> str:
    """
    Export sanitized findings and normalized evidence as CSV.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # 1. Findings Table
    writer.writerow(["SECTION", "FINDING_ID", "TEST_ID", "CATEGORY", "SEVERITY", "TITLE", "DESCRIPTION", "ENDPOINT", "POLICY_VERSION"])
    for f in report.findings:
        writer.writerow([
            "FINDING",
            f.finding_id,
            f.test_id,
            f.category,
            f.severity,
            f.title,
            f.description,
            f.endpoint,
            f.policy_version
        ])

    # 2. Evidence Table
    if evidence_items:
        writer.writerow([])
        writer.writerow(["SECTION", "EVIDENCE_ID", "TEST_ID", "CATEGORY", "SEVERITY", "CONTROL", "STATUS", "EXPECTED_BEHAVIOR", "ACTUAL_BEHAVIOR"])
        for ev in evidence_items:
            writer.writerow([
                "EVIDENCE",
                ev.evidence_id,
                ev.test_id,
                ev.category,
                ev.severity,
                ev.security_control,
                ev.status,
                ev.expected_behavior,
                ev.actual_behavior
            ])

    return output.getvalue()


def export_pdf(report: SecurityReport, evidence_items: Optional[List[EvidenceItem]] = None) -> bytes:
    """
    Export professional PDF report using reportlab.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b")
    )
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )
    badge_crit = ParagraphStyle('BadgeCrit', parent=body_style, textColor=colors.HexColor("#dc2626"), fontName="Helvetica-Bold")
    badge_pass = ParagraphStyle('BadgePass', parent=body_style, textColor=colors.HexColor("#16a34a"), fontName="Helvetica-Bold")

    story = []

    # Title & Metadata
    story.append(Paragraph(report.title, title_style))
    meta_text = (
        f"Report ID: {report.report_id} | Policy: v{report.policy_version} | "
        f"Generated: {report.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')} by {report.created_by}"
    )
    story.append(Paragraph(meta_text, subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=12))

    # Executive Summary Box
    es = report.executive_summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    exec_data = [
        [
            Paragraph(f"<b>Security Score:</b> {es.security_score}%", body_style),
            Paragraph(f"<b>Posture:</b> {es.security_posture}", body_style),
            Paragraph(f"<b>Tests Evaluated:</b> {es.total_tests}", body_style)
        ],
        [
            Paragraph(f"<b>Score Delta:</b> {es.score_delta or 0}%", body_style),
            Paragraph(f"<b>Critical Findings:</b> {es.critical_findings}", badge_crit if es.critical_findings > 0 else body_style),
            Paragraph(f"<b>Passed:</b> {es.passed_tests} / Failed: {es.failed_tests}", body_style)
        ]
    ]
    exec_table = Table(exec_data, colWidths=[180, 180, 180])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 14))

    # Category Matrix
    story.append(Paragraph("2. Security Control Domain Breakdown", h2_style))
    cat_headers = [
        Paragraph("<b>Category</b>", body_style),
        Paragraph("<b>Tests</b>", body_style),
        Paragraph("<b>Passed</b>", body_style),
        Paragraph("<b>Failed</b>", body_style),
        Paragraph("<b>Score</b>", body_style),
        Paragraph("<b>Status</b>", body_style)
    ]
    cat_rows = [cat_headers]
    for cr in report.category_results:
        cat_rows.append([
            Paragraph(cr.category, body_style),
            Paragraph(str(cr.total_tests), body_style),
            Paragraph(str(cr.passed_tests), body_style),
            Paragraph(str(cr.failed_tests), body_style),
            Paragraph(f"{cr.score}%", body_style),
            Paragraph(cr.status, badge_pass if cr.status == "PASS" else badge_crit)
        ])

    cat_table = Table(cat_rows, colWidths=[160, 60, 60, 60, 80, 80])
    cat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(cat_table)
    story.append(Spacer(1, 14))

    # Findings
    if report.findings:
        story.append(Paragraph(f"3. Security Findings ({len(report.findings)} identified)", h2_style))
        for f in report.findings[:10]:  # Cap to top 10 in PDF
            f_p = Paragraph(f"<b>[{f.severity}] {f.title}</b> ({f.test_id}) - {f.description}", body_style)
            story.append(f_p)
            story.append(Spacer(1, 4))
        story.append(Spacer(1, 10))

    # Compliance Mappings
    story.append(Paragraph("4. Framework & Standards Compliance Mappings", h2_style))
    story.append(Paragraph(f"<i>Disclaimer: {report.compliance_disclaimer}</i>", subtitle_style))
    story.append(Spacer(1, 6))

    comp_rows = [[
        Paragraph("<b>Framework</b>", body_style),
        Paragraph("<b>Control ID</b>", body_style),
        Paragraph("<b>Control Name</b>", body_style),
        Paragraph("<b>Evidence Items</b>", body_style),
        Paragraph("<b>Coverage Status</b>", body_style)
    ]]
    for cm in report.compliance_mappings[:12]:
        comp_rows.append([
            Paragraph(cm.framework, body_style),
            Paragraph(cm.control_id, body_style),
            Paragraph(cm.control_name, body_style),
            Paragraph(str(cm.evidence_count), body_style),
            Paragraph(cm.coverage_status, body_style)
        ])

    comp_table = Table(comp_rows, colWidths=[120, 80, 160, 80, 100])
    comp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(comp_table)
    story.append(Spacer(1, 14))

    # Integrity Hash & Methodology Footer
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))
    story.append(Paragraph(f"<b>SHA-256 Report Integrity Hash:</b> <code>{report.report_hash}</code>", body_style))
    story.append(Paragraph(f"<b>Methodology:</b> {report.methodology}", subtitle_style))

    doc.build(story)
    return buffer.getvalue()
