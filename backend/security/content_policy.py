import re
import logging
from typing import List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PolicyResult(BaseModel):
    """
    Structured result for corporate safety & content policy evaluation on LLM outputs.
    """
    safe: bool
    threat_type: Optional[str] = None
    risk_score: int
    matched_indicators: List[str] = Field(default_factory=list)
    action: str  # ALLOW, BLOCK


# Dangerous content patterns (heuristic rules for malicious code/exploit generation)
# Designed specifically to avoid flagging defensive cybersecurity education
UNSAFE_CONTENT_RULES = [
    # Credential dumping & Active Theft Commands
    (
        "credential_dumping_tool",
        r"(?i)\b(?:sekurlsa::logonpasswords|lsadump::sam|privilege::debug|mimikatz(?:\.exe)?\s+['\"][^'\"]*logonpasswords)\b",
        "UNSAFE_CONTENT",
        95
    ),
    (
        "sam_hive_theft_command",
        r"(?i)\breg\s+save\s+hklm\\sam\s+[a-zA-Z0-9_\\.-]+\b",
        "UNSAFE_CONTENT",
        90
    ),

    # Destructive System Commands (Unmitigated)
    (
        "destructive_unix_root_command",
        r"(?i)\brm\s+-rf\s+(?:--no-preserve-root\s+)?/\s*$",
        "UNSAFE_CONTENT",
        95
    ),
    (
        "destructive_disk_format_command",
        r"(?i)\bformat\s+[c-z]:\s+/fs:NTFS\s+/q\s+/y\b",
        "UNSAFE_CONTENT",
        95
    ),

    # Active Ransomware / Wiper Deployment Scripts
    (
        "ransomware_encryption_loop",
        r"(?i)\bfor\s+[a-zA-Z0-9_]+\s+in\s+os\.walk\([^)]*\):\s*(?:.*\n)?.*(?:AES\.new|cryptography\.fernet|encrypt_file).*\.write\(.*ransom_note",
        "UNSAFE_CONTENT",
        95
    ),
    (
        "ransom_note_instruction",
        r"(?i)\b(?:all\s+your\s+files\s+have\s+been\s+encrypted|pay\s+bitcoin\s+to\s+decrypt\s+your\s+files|send\s+[0-9.]+\s+BTC\s+to\s+[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
        "UNSAFE_CONTENT",
        90
    ),

    # Automated Reverse Shell / Backdoor Payloads
    (
        "reverse_shell_socket_payload",
        r"(?i)(?:nc\s+-e\s+/bin/(?:ba)?sh\s+[0-9.]+\s+[0-9]+|bash\s+-i\s+>& /dev/tcp/[0-9.]+|python3?\s+-c\s+['\"]import\s+socket.*s\.connect\()",
        "UNSAFE_CONTENT",
        95
    ),
]


def inspect_content_policy(text: str) -> PolicyResult:
    """
    Inspect LLM response text for dangerous / unaligned content.
    Distinguishes educational / defensive cybersecurity discussions from active attacks.
    """
    if not text or not text.strip():
        return PolicyResult(
            safe=True,
            threat_type=None,
            risk_score=0,
            matched_indicators=[],
            action="ALLOW"
        )

    matched_indicators: List[str] = []
    max_risk = 0

    for name, pattern, threat_type, score in UNSAFE_CONTENT_RULES:
        if re.search(pattern, text):
            matched_indicators.append(name)
            max_risk = max(max_risk, score)

    if max_risk >= 80:
        logger.warning(
            "Content policy violation in LLM output: indicators=%s, risk_score=%d",
            matched_indicators,
            max_risk
        )
        return PolicyResult(
            safe=False,
            threat_type="UNSAFE_CONTENT",
            risk_score=max_risk,
            matched_indicators=matched_indicators,
            action="BLOCK"
        )

    return PolicyResult(
        safe=True,
        threat_type=None,
        risk_score=max_risk,
        matched_indicators=matched_indicators,
        action="ALLOW"
    )
