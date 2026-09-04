import re
import base64
import logging
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class InjectionResult(BaseModel):
    """
    Structured result returned by the prompt injection detector.
    """
    detected: bool
    threat_type: Optional[str] = None
    risk_score: int
    matched_indicators: List[str] = Field(default_factory=list)
    action: str  # ALLOW, BLOCK


# Configurable threshold for blocking prompts (HIGH & CRITICAL risk are blocked)
DEFAULT_BLOCK_THRESHOLD = 60


# Category definitions and rule configurations
# Each rule: (name, regex_pattern, threat_type, base_score)
INJECTION_RULES = [
    # =========================================================================
    # Category A: Instruction Override
    # =========================================================================
    (
        "override_ignore_previous",
        r"(?i)\b(?:ignore|disregard|forget|skip|drop|bypass|override|negate|cancel)\s+(?:all\s+|the\s+|your\s+)?(?:prior\s+|previous\s+|above\s+|former\s+|past\s+|initial\s+|existing\s+|safety\s+|security\s+)?(?:instructions|rules|directives|prompts|guidelines|context|commands|constraints)\b",
        "INSTRUCTION_OVERRIDE",
        85
    ),
    (
        "override_forget_instructions",
        r"(?i)\bforget\s+(?:all\s+)?(?:your\s+|the\s+)?(?:instructions|rules|directives|guidelines|everything\s+you\s+(?:were|have\s+been)\s+told)\b",
        "INSTRUCTION_OVERRIDE",
        80
    ),
    (
        "override_do_not_follow",
        r"(?i)\b(?:do\s+not|don'?t|stop)\s+follow(?:ing)?\s+(?:any\s+|the\s+|your\s+)?(?:previous|prior|above|safety|security)?\s*(?:rules|instructions|directives|guidelines)\b",
        "INSTRUCTION_OVERRIDE",
        80
    ),
    (
        "override_disregard_rules",
        r"(?i)\bdisregard\s+(?:the\s+|all\s+|your\s+)?(?:safety\s+|security\s+)?(?:rules|instructions|guidelines|constraints)(?:\s+above)?\b",
        "INSTRUCTION_OVERRIDE",
        80
    ),


    # =========================================================================
    # Category B: System Prompt Extraction
    # =========================================================================
    (
        "extraction_reveal_system_prompt",
        r"(?i)\b(?:reveal|show|disclose|print|display|dump|tell\s+me|repeat|output|expose|give\s+me|leak)\s+(?:all\s+|the\s+|your\s+|me\s+(?:all\s+|the\s+|your\s+)?)?(?:hidden\s+|internal\s+|initial\s+|core\s+|original\s+|exact\s+|full\s+|secret\s+)?(?:system\s+(?:prompt|message|instructions|directive)|internal\s+instructions|hidden\s+(?:prompt|instructions)|initial\s+prompt|developer\s+prompt)\b",
        "SYSTEM_PROMPT_EXTRACTION",
        85
    ),
    (
        "extraction_what_is_system_prompt",
        r"(?i)\bwhat\s+(?:is|are|were)\s+your\s+(?:exact\s+|full\s+|hidden\s+|initial\s+|internal\s+|core\s+|original\s+)?(?:system\s+prompt|system\s+message|system\s+instructions|instructions\s+above)\b",
        "SYSTEM_PROMPT_EXTRACTION",
        75
    ),
    (
        "extraction_show_system_message",
        r"(?i)\bshow\s+(?:me\s+)?(?:the\s+|your\s+)?system\s+(?:message|prompt|instructions)\b",
        "SYSTEM_PROMPT_EXTRACTION",
        80
    ),

    # =========================================================================
    # Category C: Jailbreak & Role Manipulation
    # =========================================================================
    (
        "jailbreak_act_as_unrestricted",
        r"(?i)\bact\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|unfiltered|uncensored|evil|dan|aim|stan|maximum|developer\s+mode)\s*(?:ai|model|assistant|bot|entity|mode|persona)?\b",
        "JAILBREAK",
        90
    ),
    (
        "jailbreak_enable_mode",
        r"(?i)\b(?:enable|enter|activate|turn\s+on|switch\s+to)\s+(?:developer\s+mode|god\s+mode|jailbreak\s+mode|unrestricted\s+mode|dan\s+mode|unfiltered\s+mode)\b",
        "JAILBREAK",
        85
    ),
    (
        "jailbreak_bypass_safety",
        r"(?i)\b(?:bypass|disable|circumvent|turn\s+off|remove|drop|ignore)\s+(?:all\s+)?(?:your\s+)?(?:safety|content|security|ethical|moderation)\s+(?:rules|restrictions|filters|guidelines|guardrails|policies|limits)\b",
        "JAILBREAK",
        90
    ),
    (
        "jailbreak_pretend_no_restrictions",
        r"(?i)\bpretend\s+(?:that\s+)?(?:you\s+have\s+no|all\s+(?:safety\s+)?rules\s+are\s+disabled|(?:all|your|the)\s+safety\s+rules\s+are\s+disabled|(?:safety\s+|security\s+)?rules\s+are\s+disabled|you\s+have\s+no\s+(?:rules|restrictions|filters|guidelines|limits|guardrails|safety))\b",
        "JAILBREAK",
        85
    ),
    (
        "jailbreak_you_are_now_dan",
        r"(?i)\byou\s+are\s+now\s+(?:unrestricted|jailbroken|free\s+from\s+all\s+rules|dan|in\s+developer\s+mode)\b",
        "JAILBREAK",
        90
    ),


    # =========================================================================
    # Category D: Instruction Hierarchy Manipulation & Framing
    # =========================================================================
    (
        "hierarchy_system_prefix",
        r"(?i)(?:^|\n)\s*(?:\[(?:system|admin|developer|root)\]|<\|im_start\|>system|<system>|system\s+instruction\s*:|developer\s+instruction\s*:|highest\s+priority\s+instruction\s*:|new\s+system\s+(?:message|instruction|directive)\s*:)",
        "HIERARCHY_MANIPULATION",
        80
    ),
    (
        "hierarchy_real_instructions",
        r"(?i)\byour\s+(?:real|actual|true|new)\s+instructions\s+(?:are|now\s+are)\b",
        "HIERARCHY_MANIPULATION",
        75
    ),
]


def _normalize_text(text: str) -> str:
    """
    Remove zero-width characters and excessive whitespace without mutating the prompt semantics.
    """
    cleaned = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff]", "", text)
    return cleaned


def _check_base64_obfuscation(text: str) -> Tuple[bool, List[str], int]:
    """
    Detect Base64 chunks and check if decoded contents contain injection indicators.
    """
    b64_candidates = re.findall(
        r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        text
    )
    matched_obfuscated: List[str] = []
    max_b64_score = 0

    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            # Check if decoded payload contains injection patterns
            for name, pattern, threat_type, score in INJECTION_RULES:
                if re.search(pattern, decoded):
                    matched_obfuscated.append(f"base64_encoded_{name}")
                    max_b64_score = max(max_b64_score, 90)
        except Exception:
            continue

    return (len(matched_obfuscated) > 0, matched_obfuscated, max_b64_score)


def inspect_prompt_injection(
    prompt: str,
    block_threshold: int = DEFAULT_BLOCK_THRESHOLD
) -> InjectionResult:
    """
    Inspect a prompt for prompt injection, jailbreak attempts, system prompt extraction,
    hierarchy manipulation, and obfuscated attack vectors.
    """
    if not prompt or not prompt.strip():
        return InjectionResult(
            detected=False,
            threat_type=None,
            risk_score=0,
            matched_indicators=[],
            action="ALLOW"
        )

    normalized_prompt = _normalize_text(prompt)
    matched_indicators: List[str] = []
    matched_threat_types: List[str] = []
    highest_score = 0

    # 1. Pattern-based rule evaluation across categories A-D
    for name, pattern, threat_type, score in INJECTION_RULES:
        if re.search(pattern, normalized_prompt):
            matched_indicators.append(name)
            matched_threat_types.append(threat_type)
            highest_score = max(highest_score, score)

    # 2. Obfuscation & Base64 attack check (Category E)
    has_b64, b64_indicators, b64_score = _check_base64_obfuscation(normalized_prompt)
    if has_b64:
        matched_indicators.extend(b64_indicators)
        matched_threat_types.append("OBFUSCATED_ATTEMPT")
        highest_score = max(highest_score, b64_score)

    # 3. Multi-indicator escalation
    # If multiple distinct injection rules matched, elevate risk score
    if len(matched_indicators) > 1:
        composite_score = min(100, highest_score + (len(matched_indicators) - 1) * 10)
    else:
        composite_score = highest_score

    # Determine primary threat type
    primary_threat = None
    if matched_threat_types:
        if "JAILBREAK" in matched_threat_types:
            primary_threat = "JAILBREAK"
        elif "SYSTEM_PROMPT_EXTRACTION" in matched_threat_types:
            primary_threat = "SYSTEM_PROMPT_EXTRACTION"
        elif "INSTRUCTION_OVERRIDE" in matched_threat_types:
            primary_threat = "INSTRUCTION_OVERRIDE"
        elif "HIERARCHY_MANIPULATION" in matched_threat_types:
            primary_threat = "HIERARCHY_MANIPULATION"
        elif "OBFUSCATED_ATTEMPT" in matched_threat_types:
            primary_threat = "PROMPT_INJECTION"
        else:
            primary_threat = "PROMPT_INJECTION"

    # Action determination: HIGH / CRITICAL (score >= threshold) are BLOCKED
    action = "BLOCK" if composite_score >= block_threshold else "ALLOW"
    detected = composite_score >= 30

    if detected:
        logger.warning(
            "Prompt injection analysis: detected=%s, risk_score=%d, threat_type=%s, action=%s, indicators_count=%d",
            detected,
            composite_score,
            primary_threat,
            action,
            len(matched_indicators)
        )

    return InjectionResult(
        detected=detected,
        threat_type=primary_threat if detected else None,
        risk_score=composite_score,
        matched_indicators=matched_indicators,
        action=action
    )
