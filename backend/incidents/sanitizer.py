import re
from typing import Any, Dict, List, Union, Optional
from backend.reporting.sanitizer import (
    sanitize_text as base_sanitize_text,
    sanitize_metadata as base_sanitize_metadata,
    FORBIDDEN_RAW_KEYS,
    REDACTION_PATTERNS
)


def sanitize_incident_text(text: Optional[str]) -> str:
    """
    Sanitize text strings for incident titles, descriptions, and analyst notes.
    Strips raw secrets, API keys, tokens, credentials, and PII while preserving
    incident classification terms.
    """
    return base_sanitize_text(text)


def sanitize_incident_metadata(data: Union[Dict[str, Any], List[Any], Any]) -> Any:
    """
    Recursively scrub metadata dictionary or list to ensure no sensitive keys,
    passwords, tokens, or raw prompts/responses are stored.
    """
    return base_sanitize_metadata(data)


def sanitize_incident_note(note: str) -> str:
    """
    Sanitize an analyst note before persistence.
    """
    return base_sanitize_text(note)


def sanitize_evidence_payload(
    description: str,
    raw_content: Optional[str] = None
) -> str:
    """
    Sanitize evidence description and generate safe evidence summary representation.
    Guaranteed to redact passwords, bearer tokens, API keys, and sensitive payloads.
    """
    clean_desc = base_sanitize_text(description)
    if raw_content:
        clean_content = base_sanitize_text(raw_content)
        return f"{clean_desc} | Summary: {clean_content[:200]}"
    return clean_desc
