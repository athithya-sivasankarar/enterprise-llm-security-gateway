import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from backend.campaign.models import BaselineComparisonResult, RegressionItem


def compare_runs_with_baseline(
    campaign_id: str,
    campaign_run_id: str,
    current_run_id: str,
    current_results: List[Any],
    current_score: float,
    current_policy_version: str = "1.0.0",
    baseline_run_id: Optional[str] = None,
    baseline_results: Optional[List[Any]] = None,
    baseline_score: Optional[float] = None
) -> BaselineComparisonResult:
    """
    Compare individual test results from the current run against baseline records by test_id.
    Strictly evaluates:
    - baseline.status == PASS and current.status in (FAIL, ERROR) -> Regression
    - baseline.status in (FAIL, ERROR) and current.status == PASS -> Resolved failure
    - Category pass rate deltas
    - Added and removed tests
    """
    if not baseline_results or baseline_run_id is None:
        # First run or no baseline set yet
        return BaselineComparisonResult(
            campaign_id=campaign_id,
            baseline_run_id=None,
            current_run_id=current_run_id,
            baseline_score=None,
            current_score=current_score,
            score_delta=0.0,
            regression_detected=False,
            new_failures=[],
            new_errors=[],
            resolved_failures=[],
            categories_regressed=[],
            category_deltas={},
            regressions=[],
            added_tests=[getattr(r, "test_id", "") for r in current_results],
            removed_tests=[]
        )

    # Index by test_id
    base_map = {getattr(r, "test_id", ""): r for r in baseline_results if getattr(r, "test_id", "")}
    curr_map = {getattr(r, "test_id", ""): r for r in current_results if getattr(r, "test_id", "")}

    eff_baseline_score = baseline_score
    if eff_baseline_score is None and baseline_results:
        b_pass = sum(1 for r in baseline_results if getattr(r, "status", "").upper() == "PASS")
        b_eval = sum(1 for r in baseline_results if getattr(r, "status", "").upper() in ("PASS", "FAIL", "ERROR"))
        eff_baseline_score = round((b_pass / b_eval) * 100.0, 2) if b_eval > 0 else 0.0

    score_delta = round(current_score - (eff_baseline_score if eff_baseline_score is not None else current_score), 2)

    new_failures: List[str] = []
    new_errors: List[str] = []
    resolved_failures: List[str] = []
    categories_regressed: set = set()
    regressions: List[RegressionItem] = []

    # Check tests present in current run
    for test_id, curr_r in curr_map.items():
        curr_status = getattr(curr_r, "status", "UNKNOWN").upper()
        category = getattr(curr_r, "category", "GENERAL")
        severity = getattr(curr_r, "severity", "MEDIUM")

        if test_id in base_map:
            base_r = base_map[test_id]
            base_status = getattr(base_r, "status", "UNKNOWN").upper()

            # Regression detection rule
            if base_status == "PASS" and curr_status in ("FAIL", "ERROR"):
                if curr_status == "FAIL":
                    new_failures.append(test_id)
                else:
                    new_errors.append(test_id)

                categories_regressed.add(category)

                err_msg = getattr(curr_r, "error_message", None)
                desc = f"Regression detected in test {test_id} ({category}): Status regressed from {base_status} to {curr_status}."
                if err_msg:
                    desc += f" Reason: {err_msg}"

                reg_id = f"reg-{uuid.uuid4().hex[:12]}"
                reg_item = RegressionItem(
                    regression_id=reg_id,
                    campaign_run_id=campaign_run_id,
                    campaign_id=campaign_id,
                    test_id=test_id,
                    category=category,
                    severity=severity,
                    previous_status=base_status,
                    current_status=curr_status,
                    previous_score=eff_baseline_score,
                    current_score=current_score,
                    score_delta=score_delta,
                    policy_version=current_policy_version,
                    baseline_run_id=baseline_run_id,
                    current_run_id=current_run_id,
                    description=desc,
                    created_at=datetime.now(timezone.utc)
                )
                regressions.append(reg_item)

            elif base_status in ("FAIL", "ERROR") and curr_status == "PASS":
                resolved_failures.append(test_id)

    # Added / removed test catalog changes
    added_tests = sorted(list(set(curr_map.keys()) - set(base_map.keys())))
    removed_tests = sorted(list(set(base_map.keys()) - set(curr_map.keys())))

    # Category breakdowns
    all_cats = set([getattr(r, "category", "") for r in current_results] + [getattr(r, "category", "") for r in baseline_results])
    category_deltas: Dict[str, Dict[str, Any]] = {}

    for cat in sorted(all_cats):
        if not cat:
            continue
        c_curr = [r for r in current_results if getattr(r, "category", "") == cat]
        c_base = [r for r in baseline_results if getattr(r, "category", "") == cat]

        c_curr_pass = sum(1 for r in c_curr if getattr(r, "status", "").upper() == "PASS")
        c_curr_rate = round((c_curr_pass / len(c_curr)) * 100.0, 2) if c_curr else 0.0

        c_base_pass = sum(1 for r in c_base if getattr(r, "status", "").upper() == "PASS")
        c_base_rate = round((c_base_pass / len(c_base)) * 100.0, 2) if c_base else 0.0

        c_delta = round(c_curr_rate - c_base_rate, 2)

        category_deltas[cat] = {
            "baseline_pass_rate": c_base_rate,
            "current_pass_rate": c_curr_rate,
            "delta": c_delta,
            "regressed": c_delta < 0 or cat in categories_regressed
        }

    regression_detected = len(regressions) > 0

    return BaselineComparisonResult(
        campaign_id=campaign_id,
        baseline_run_id=baseline_run_id,
        current_run_id=current_run_id,
        baseline_score=eff_baseline_score,
        current_score=current_score,
        score_delta=score_delta,
        regression_detected=regression_detected,
        new_failures=sorted(new_failures),
        new_errors=sorted(new_errors),
        resolved_failures=sorted(resolved_failures),
        categories_regressed=sorted(list(categories_regressed)),
        category_deltas=category_deltas,
        regressions=regressions,
        added_tests=added_tests,
        removed_tests=removed_tests
    )
