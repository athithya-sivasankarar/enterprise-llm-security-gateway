from typing import List
from backend.campaign.models import RegressionItem


def format_regression_alert(regression: RegressionItem) -> str:
    """
    Format a clean alert string for SIEM notifications and SOC dashboards.
    """
    return (
        f"[REGRESSION ALERT] [{regression.severity}] Test: {regression.test_id} ({regression.category}) "
        f"Regressed from {regression.previous_status} to {regression.current_status} | "
        f"Score Delta: {regression.score_delta}% | Policy: v{regression.policy_version}"
    )


def filter_critical_regressions(regressions: List[RegressionItem]) -> List[RegressionItem]:
    """
    Filter regressions by high/critical severity.
    """
    return [r for r in regressions if r.severity in ("CRITICAL", "HIGH")]
