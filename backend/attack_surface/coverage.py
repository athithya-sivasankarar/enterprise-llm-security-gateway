import logging
from typing import List, Dict, Any, Optional
from backend.attack_surface.models import AssetCoverageDetail, SecurityAsset
from backend.control_coverage.engine import STANDARD_SECURITY_CONTROLS

logger = logging.getLogger(__name__)


def calculate_asset_multidimensional_coverage(
    asset: SecurityAsset,
    test_results_map: Dict[str, Any],
    findings_count: int = 0,
    active_incidents_count: int = 0,
    exposures_count: int = 0
) -> AssetCoverageDetail:
    """
    Calculate deterministic multidimensional security coverage for an inventoried asset.
    """
    controls_mapped: List[str] = []
    tests_mapped: List[str] = []

    atype = asset.asset_type.upper()

    # Map relevant controls based on asset type
    for ctrl in STANDARD_SECURITY_CONTROLS:
        domain = ctrl["domain"]
        if atype in ("LLM_MODEL", "LLM_PROVIDER"):
            # Models/Providers are protected by Prompt Injection, Jailbreak, System Prompt, Secret Leakage, Unsafe Content, Response PII, RBAC
            if domain in ("PROMPT_INJECTION", "JAILBREAK", "SYSTEM_PROMPT_EXTRACTION", "SECRET_LEAKAGE", "UNSAFE_CONTENT", "RESPONSE_PII", "RBAC"):
                controls_mapped.append(ctrl["control_id"])
                tests_mapped.extend(ctrl["tests_mapped"])
        elif atype in ("API", "ENDPOINT"):
            # Endpoints are protected by Auth, Rate Limiting, Input DLP, RBAC, Policy
            if domain in ("AUTHENTICATION", "RATE_LIMITING", "INPUT_DLP", "RBAC", "POLICY", "AUDIT"):
                controls_mapped.append(ctrl["control_id"])
                tests_mapped.extend(ctrl["tests_mapped"])
        elif atype == "CACHE":
            if domain in ("CACHE_ISOLATION", "AUTHENTICATION"):
                controls_mapped.append(ctrl["control_id"])
                tests_mapped.extend(ctrl["tests_mapped"])
        else:
            controls_mapped.append(ctrl["control_id"])
            tests_mapped.extend(ctrl["tests_mapped"])

    unique_tests = list(set(tests_mapped))
    executed_tests = sum(1 for tid in unique_tests if tid in test_results_map)
    cov_pct = (executed_tests / len(unique_tests)) * 100.0 if unique_tests else 100.0

    return AssetCoverageDetail(
        asset=asset,
        controls_mapped=list(set(controls_mapped)),
        tests_mapped=unique_tests,
        findings_count=findings_count,
        active_incidents_count=active_incidents_count,
        exposures_count=exposures_count,
        coverage_pct=round(cov_pct, 1),
        risk_score=asset.risk_score
    )
