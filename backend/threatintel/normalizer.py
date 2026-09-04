import re
from typing import Tuple, Optional

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
CWE_PATTERN = re.compile(r"^CWE-\d{1,5}$", re.IGNORECASE)
ATTACK_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
ATLAS_PATTERN = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
OWASP_LLM_PATTERN = re.compile(r"^LLM\d{2}$", re.IGNORECASE)
OWASP_TOP10_PATTERN = re.compile(r"^A\d{2}(?::\d{4})?$", re.IGNORECASE)


def normalize_cve(cve: str) -> Optional[str]:
    clean = str(cve).strip().upper()
    if CVE_PATTERN.match(clean):
        return clean
    # Try fixing cve-2024-0001
    if not clean.startswith("CVE-") and re.match(r"^\d{4}-\d{4,7}$", clean):
        candidate = f"CVE-{clean}"
        if CVE_PATTERN.match(candidate):
            return candidate
    return None


def normalize_cwe(cwe: str) -> Optional[str]:
    clean = str(cwe).strip().upper()
    if CWE_PATTERN.match(clean):
        return clean
    if clean.isdigit():
        return f"CWE-{clean}"
    return None


def normalize_attack(attack: str) -> Optional[str]:
    clean = str(attack).strip().upper()
    if ATTACK_PATTERN.match(clean):
        return clean
    return None


def normalize_atlas(atlas: str) -> Optional[str]:
    clean = str(atlas).strip().upper()
    if ATLAS_PATTERN.match(clean):
        return clean
    if clean.startswith("T") and re.match(r"^T\d{4}(?:\.\d{3})?$", clean):
        return f"AML.{clean}"
    return None


def normalize_owasp(owasp: str) -> Optional[str]:
    clean = str(owasp).strip().upper()
    if OWASP_LLM_PATTERN.match(clean):
        return clean
    if OWASP_TOP10_PATTERN.match(clean):
        return clean
    if clean.isdigit() and len(clean) == 2:
        return f"LLM{clean}"
    return None


def normalize_indicator(indicator_type: str, indicator: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate and normalize threat indicator.
    Returns: (is_valid, normalized_indicator, error_message)
    """
    raw_type = str(indicator_type).strip().upper()
    raw_ind = str(indicator).strip()

    if not raw_ind:
        return False, "", "Indicator cannot be empty"

    if raw_type == "CVE":
        norm = normalize_cve(raw_ind)
        if norm:
            return True, norm, None
        return False, raw_ind, f"Invalid CVE format '{raw_ind}'. Expected CVE-YYYY-NNNN"

    elif raw_type == "CWE":
        norm = normalize_cwe(raw_ind)
        if norm:
            return True, norm, None
        return False, raw_ind, f"Invalid CWE format '{raw_ind}'. Expected CWE-NNN"

    elif raw_type == "ATLAS_TECHNIQUE":
        norm = normalize_atlas(raw_ind)
        if norm:
            return True, norm, None
        return False, raw_ind, f"Invalid MITRE ATLAS format '{raw_ind}'. Expected AML.TNNNN"

    elif raw_type == "ATTACK_TECHNIQUE":
        norm = normalize_attack(raw_ind)
        if norm:
            return True, norm, None
        return False, raw_ind, f"Invalid MITRE ATT&CK format '{raw_ind}'. Expected TNNNN"

    elif raw_type == "OWASP_CATEGORY":
        norm = normalize_owasp(raw_ind)
        if norm:
            return True, norm, None
        return False, raw_ind, f"Invalid OWASP format '{raw_ind}'. Expected LLM01-LLM10 or A01:2021"

    elif raw_type in ("CONTROL_WEAKNESS", "THREAT_PATTERN"):
        clean_pattern = raw_ind.strip().upper().replace(" ", "_")
        return True, clean_pattern, None

    return False, raw_ind, f"Unsupported indicator type '{indicator_type}'"
