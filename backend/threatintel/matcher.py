import logging
from typing import List, Optional, Dict, Any
from backend.threatintel.models import ThreatIntelMatch, ThreatIntelItem
from backend.threatintel.scoring import calculate_threat_relevance_score

logger = logging.getLogger(__name__)


def match_threat_intel_for_category(
    category: str,
    intel_items: List[Dict[str, Any]],
    target_type: str = "TEST",
    target_id: str = "unknown",
    has_active_regression: bool = False,
    has_active_incident: bool = False,
    is_critical_asset: bool = False,
    has_control_gap: bool = False
) -> List[ThreatIntelMatch]:
    """
    Deterministically match threat intelligence items to a security category / target.
    """
    matches: List[ThreatIntelMatch] = []
    norm_cat = str(category).strip().upper()

    for item in intel_items:
        item_cat = str(item.get("category", "")).strip().upper()
        if item_cat == norm_cat:
            sev = item.get("severity", "MEDIUM")
            conf = float(item.get("confidence", 0.9))

            rel_score = calculate_threat_relevance_score(
                severity=sev,
                confidence=conf,
                has_active_regression=has_active_regression,
                has_active_incident=has_active_incident,
                is_critical_asset=is_critical_asset,
                has_control_gap=has_control_gap
            )

            matches.append(
                ThreatIntelMatch(
                    intel_id=item.get("intel_id", "intel-unknown"),
                    indicator=item.get("indicator", ""),
                    indicator_type=item.get("indicator_type", "THREAT_PATTERN"),
                    category=item_cat,
                    severity=sev,
                    confidence=conf,
                    relevance_score=rel_score,
                    description=item.get("description", ""),
                    matched_target_type=target_type,
                    matched_target_id=target_id,
                    match_reason=f"Matched domain category '{norm_cat}' to {item.get('indicator_type')} indicator '{item.get('indicator')}'"
                )
            )

    matches.sort(key=lambda m: (m.relevance_score, m.confidence), reverse=True)
    return matches
