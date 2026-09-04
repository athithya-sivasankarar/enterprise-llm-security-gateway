import logging
from typing import Optional

logger = logging.getLogger(__name__)

SEVERITY_SCORES = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0
}


def calculate_threat_relevance_score(
    severity: str,
    confidence: float,
    has_active_regression: bool = False,
    has_active_incident: bool = False,
    is_critical_asset: bool = False,
    has_control_gap: bool = False
) -> int:
    """
    Deterministically calculate threat intelligence relevance score (0-100).
    """
    norm_sev = str(severity).strip().upper()
    base = SEVERITY_SCORES.get(norm_sev, 10)

    # Scale base by confidence (e.g. 40 * 0.95 = 38)
    clamped_conf = max(0.1, min(1.0, float(confidence)))
    score = base * clamped_conf

    if has_active_regression:
        score += 20
    if has_active_incident:
        score += 20
    if is_critical_asset:
        score += 15
    if has_control_gap:
        score += 15

    return max(0, min(100, int(round(score))))
