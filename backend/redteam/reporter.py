from typing import List, Dict, Any
from backend.redteam.models import (
    SecurityTestResult,
    SecurityTestFinding,
    SecurityReport,
    CategorySummary
)
from backend.redteam.categories import TestStatus


def generate_security_report(
    run_id: str,
    status: str,
    policy_version: str,
    started_at: Any,
    completed_at: Any,
    created_by: str,
    results: List[SecurityTestResult],
    findings: List[SecurityTestFinding]
) -> SecurityReport:
    """
    Compute category metrics, calculate security score, and compile normalized SecurityReport.
    """
    total = len(results)
    passed = sum(1 for r in results if r.status == TestStatus.PASS.value)
    failed = sum(1 for r in results if r.status == TestStatus.FAIL.value)
    errored = sum(1 for r in results if r.status == TestStatus.ERROR.value)
    skipped = sum(1 for r in results if r.status == TestStatus.SKIPPED.value)

    # Score calculation: passed / total_evaluated * 100
    evaluated = total - skipped
    if evaluated > 0:
        security_score = round((passed / evaluated) * 100.0, 2)
    else:
        security_score = 0.0

    # Group by category
    categories_map: Dict[str, List[SecurityTestResult]] = {}
    for r in results:
        categories_map.setdefault(r.category, []).append(r)

    category_summaries: List[CategorySummary] = []
    for cat, cat_results in sorted(categories_map.items()):
        c_total = len(cat_results)
        c_pass = sum(1 for r in cat_results if r.status == TestStatus.PASS.value)
        c_fail = sum(1 for r in cat_results if r.status == TestStatus.FAIL.value)
        c_err = sum(1 for r in cat_results if r.status == TestStatus.ERROR.value)
        c_skip = sum(1 for r in cat_results if r.status == TestStatus.SKIPPED.value)
        c_eval = c_total - c_skip
        c_rate = round((c_pass / c_eval) * 100.0, 2) if c_eval > 0 else 0.0

        category_summaries.append(
            CategorySummary(
                category=cat,
                total=c_total,
                passed=c_pass,
                failed=c_fail,
                errors=c_err,
                skipped=c_skip,
                pass_rate=c_rate
            )
        )

    summary_data = {
        "total_tests": total,
        "passed_tests": passed,
        "failed_tests": failed,
        "error_tests": errored,
        "skipped_tests": skipped,
        "security_score": security_score,
        "critical_findings": sum(1 for f in findings if f.severity == "CRITICAL"),
        "high_findings": sum(1 for f in findings if f.severity == "HIGH"),
        "medium_findings": sum(1 for f in findings if f.severity == "MEDIUM"),
        "low_findings": sum(1 for f in findings if f.severity == "LOW")
    }

    return SecurityReport(
        run_id=run_id,
        status=status,
        security_score=security_score,
        policy_version=policy_version,
        started_at=started_at,
        completed_at=completed_at,
        created_by=created_by,
        summary=summary_data,
        category_summaries=category_summaries,
        findings=findings,
        test_results=results
    )


def format_text_report(report: SecurityReport) -> str:
    """
    Format a clean, readable ASCII / text security validation report for CLI.
    Never exposes raw sensitive values or API keys.
    """
    lines = [
        "================================================================================",
        "          ENTERPRISE LLM SECURITY GATEWAY — SECURITY VALIDATION REPORT",
        "================================================================================",
        f" Run ID         : {report.run_id}",
        f" Status         : {report.status}",
        f" Security Score : {report.security_score}%",
        f" Policy Version : {report.policy_version}",
        f" Started At     : {report.started_at.isoformat() if hasattr(report.started_at, 'isoformat') else report.started_at}",
        f" Completed At   : {report.completed_at.isoformat() if hasattr(report.completed_at, 'isoformat') else report.completed_at}",
        f" Triggered By   : {report.created_by}",
        "--------------------------------------------------------------------------------",
        " SUMMARY BREAKDOWN",
        "--------------------------------------------------------------------------------",
        f" Total Assertions : {report.summary.get('total_tests', 0)}",
        f" Passed           : {report.summary.get('passed_tests', 0)}",
        f" Failed           : {report.summary.get('failed_tests', 0)}",
        f" Errors           : {report.summary.get('error_tests', 0)}",
        f" Skipped          : {report.summary.get('skipped_tests', 0)}",
        f" Critical Findings: {report.summary.get('critical_findings', 0)}",
        f" High Findings    : {report.summary.get('high_findings', 0)}",
        "--------------------------------------------------------------------------------",
        " CATEGORY RESULTS",
        "--------------------------------------------------------------------------------",
        f" {'Category':<28} | {'Total':<6} | {'Pass':<6} | {'Fail':<6} | {'Pass Rate':<10}",
        "-" * 80
    ]

    for c in report.category_summaries:
        lines.append(
            f" {c.category:<28} | {c.total:<6} | {c.passed:<6} | {c.failed:<6} | {c.pass_rate:.1f}%"
        )

    if report.findings:
        lines.extend([
            "--------------------------------------------------------------------------------",
            " SECURITY FINDINGS",
            "--------------------------------------------------------------------------------"
        ])
        for f in report.findings:
            lines.append(f" [{f.severity}] {f.test_id} — {f.title}")
            lines.append(f"   Expected: {f.expected_behavior}")
            lines.append(f"   Actual  : {f.actual_behavior}")
            lines.append(f"   Endpoint: {f.endpoint}")
            lines.append("")
    else:
        lines.extend([
            "--------------------------------------------------------------------------------",
            " No security findings detected. All gateway controls verified successfully.",
            "--------------------------------------------------------------------------------"
        ])

    lines.append("================================================================================")
    return "\n".join(lines)
