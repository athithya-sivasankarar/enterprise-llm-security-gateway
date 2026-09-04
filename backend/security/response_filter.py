import re
import logging
from typing import List, Optional
from pydantic import BaseModel, Field

from backend.security.dlp import get_analyzer, get_anonymizer, calculate_risk_score, TARGET_PII_ENTITIES
from backend.security.content_policy import inspect_content_policy

logger = logging.getLogger(__name__)


class ResponseFilterResult(BaseModel):
    """
    Structured result returned by the LLM response security filter.
    """
    safe: bool
    sanitized_response: str
    risk_score: int
    action: str  # ALLOW, SANITIZE, BLOCK
    detected_entities: List[str] = Field(default_factory=list)
    threat_type: Optional[str] = None


# High-confidence credential and secret assignment patterns in LLM outputs
SECRET_LEAKAGE_PATTERNS = [
    # Explicit AWS Access Key ID
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    # OpenAI and standard API Keys
    ("openai_api_key", r"\bsk-[a-zA-Z0-9_-]{20,}\b"),
    # Bearer Tokens
    ("bearer_token", r"\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b"),
    # RSA / EC Private Key Headers
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    # Direct Password / Secret Assignments (e.g. password=Secret123, api_key="abc...")
    ("password_assignment", r"(?i)\b(?:password|passwd|pwd|api_secret|client_secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    ("generic_api_key_assignment", r"(?i)\b(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?"),
]


def _check_secret_leakage(text: str) -> bool:
    """
    Check if LLM output contains unmasked operational secrets or credentials.
    """
    for name, pattern in SECRET_LEAKAGE_PATTERNS:
        if re.search(pattern, text):
            return True
    return False


def inspect_response(response: str, block_threshold: int = 80) -> ResponseFilterResult:
    """
    Inspect an LLM response before returning it to the client.
    1. Evaluates content safety policy (malicious code/theft commands).
    2. Scans for high-risk credential & secret leakage (triggers BLOCK).
    3. Scans for PII via Presidio DLP (triggers SANITIZE).
    4. Never leaks raw sensitive values.
    """
    if not response or not response.strip():
        return ResponseFilterResult(
            safe=True,
            sanitized_response=response,
            risk_score=0,
            action="ALLOW",
            detected_entities=[],
            threat_type=None
        )

    # 1. Evaluate Dangerous Content Policy
    policy_result = inspect_content_policy(response)
    if policy_result.action == "BLOCK" or policy_result.risk_score >= block_threshold:
        logger.warning(
            "Response blocked by Content Policy: risk_score=%d",
            policy_result.risk_score
        )
        return ResponseFilterResult(
            safe=False,
            sanitized_response="",
            risk_score=policy_result.risk_score,
            action="BLOCK",
            detected_entities=[],
            threat_type="UNSAFE_CONTENT"
        )

    # 2. Check for High-Risk Secret / Credential Leakage
    if _check_secret_leakage(response):
        logger.warning("Response blocked: Secret / Credential leakage detected in LLM output")
        return ResponseFilterResult(
            safe=False,
            sanitized_response="",
            risk_score=95,
            action="BLOCK",
            detected_entities=["SECRET_CREDENTIAL"],
            threat_type="SECRET_LEAKAGE"
        )

    # 3. Scan for PII & Sanitize using Presidio
    analyzer = get_analyzer()
    anonymizer = get_anonymizer()

    results = analyzer.analyze(
        text=response,
        language="en",
        entities=TARGET_PII_ENTITIES,
        score_threshold=0.35
    )

    if results:
        # Redact PII entities
        anonymized = anonymizer.anonymize(text=response, analyzer_results=results)
        sanitized_text = anonymized.text

        detected_entities = sorted(list(set(r.entity_type for r in results)))
        if "EMAIL_ADDRESS" in detected_entities and "URL" in detected_entities:
            detected_entities.remove("URL")

        pii_risk_score = calculate_risk_score(detected_entities)

        logger.info(
            "Response PII sanitized: entities=%s, risk_score=%d",
            detected_entities,
            pii_risk_score
        )

        return ResponseFilterResult(
            safe=True,
            sanitized_response=sanitized_text,
            risk_score=pii_risk_score,
            action="SANITIZE",
            detected_entities=detected_entities,
            threat_type=None
        )

    # 4. Clean and safe response
    return ResponseFilterResult(
        safe=True,
        sanitized_response=response,
        risk_score=0,
        action="ALLOW",
        detected_entities=[],
        threat_type=None
    )
