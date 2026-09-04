from typing import List, Dict, Any, Tuple, Optional
from backend.reporting.models import CategoryResult


def calculate_overall_score(passed_tests: int, total_evaluated_tests: int) -> float:
    """
    Calculate aggregate security score percentage using Step 15/16 deterministic formula:
    Score = (Passed Tests / Evaluated Tests) * 100.0
    """
    if total_evaluated_tests <= 0:
        return 100.0
    return round((passed_tests / total_evaluated_tests) * 100.0, 2)


def calculate_category_results(test_results: List[Any]) -> List[CategoryResult]:
    """
    Compute per-category security score breakdown from normalized test results.
    """
    cat_buckets: Dict[str, Dict[str, int]] = {}

    for tr in test_results:
        cat = getattr(tr, "category", "UNKNOWN").upper()
        stat = getattr(tr, "status", "UNKNOWN").upper()

        if cat not in cat_buckets:
            cat_buckets[cat] = {"total": 0, "passed": 0, "failed": 0, "errors": 0}

        cat_buckets[cat]["total"] += 1
        if stat == "PASS":
            cat_buckets[cat]["passed"] += 1
        elif stat == "FAIL":
            cat_buckets[cat]["failed"] += 1
        elif stat == "ERROR":
            cat_buckets[cat]["errors"] += 1

    results: List[CategoryResult] = []
    for cat, counts in sorted(cat_buckets.items()):
        total = counts["total"]
        passed = counts["passed"]
        score = calculate_overall_score(passed, total)
        cat_status = "PASS" if score >= 90.0 else "DEGRADED" if score >= 70.0 else "FAIL"
        results.append(
            CategoryResult(
                category=cat,
                total_tests=total,
                passed_tests=passed,
                failed_tests=counts["failed"],
                error_tests=counts["errors"],
                score=score,
                status=cat_status
            )
        )
    return results


def determine_security_posture(
    score: float,
    critical_findings: int = 0,
    high_findings: int = 0,
    critical_alerts: int = 0,
    high_alerts: int = 0
) -> str:
    """
    Determine security posture classification matching Step 17 semantics:
    - CRITICAL: score < 70.0 or critical_findings > 0 or critical_alerts > 0
    - DEGRADED: 70.0 <= score < 90.0 or high_findings > 0 or high_alerts > 0
    - SECURE: score >= 90.0 and no critical/high issues
    """
    if score < 70.0 or critical_findings > 0 or critical_alerts > 0:
        return "CRITICAL"
    elif score < 90.0 or high_findings > 0 or high_alerts > 0:
        return "DEGRADED"
    else:
        return "SECURE"
