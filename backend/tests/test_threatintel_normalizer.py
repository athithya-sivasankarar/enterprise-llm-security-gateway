import pytest
from backend.threatintel.normalizer import (
    normalize_cve,
    normalize_cwe,
    normalize_atlas,
    normalize_attack,
    normalize_owasp,
    normalize_indicator
)


def test_normalize_cve():
    assert normalize_cve("cve-2024-12345") == "CVE-2024-12345"
    assert normalize_cve("2024-12345") == "CVE-2024-12345"
    assert normalize_cve("CVE-2023-9999999") == "CVE-2023-9999999"
    assert normalize_cve("invalid-cve") is None
    assert normalize_cve("CVE-24-123") is None


def test_normalize_cwe():
    assert normalize_cwe("cwe-77") == "CWE-77"
    assert normalize_cwe("798") == "CWE-798"
    assert normalize_cwe("CWE-359") == "CWE-359"
    assert normalize_cwe("invalid") is None


def test_normalize_atlas():
    assert normalize_atlas("aml.t0054") == "AML.T0054"
    assert normalize_atlas("T0054") == "AML.T0054"
    assert normalize_atlas("AML.T0051.001") == "AML.T0051.001"
    assert normalize_atlas("invalid") is None


def test_normalize_attack():
    assert normalize_attack("t1059") == "T1059"
    assert normalize_attack("T1059.001") == "T1059.001"
    assert normalize_attack("invalid") is None


def test_normalize_owasp():
    assert normalize_owasp("llm01") == "LLM01"
    assert normalize_owasp("06") == "LLM06"
    assert normalize_owasp("A01:2021") == "A01:2021"
    assert normalize_owasp("invalid") is None


def test_normalize_indicator_full():
    valid, norm, err = normalize_indicator("CVE", "cve-2024-0001")
    assert valid is True
    assert norm == "CVE-2024-0001"
    assert err is None

    valid, norm, err = normalize_indicator("ATLAS_TECHNIQUE", "aml.t0054")
    assert valid is True
    assert norm == "AML.T0054"

    valid, norm, err = normalize_indicator("CWE", "invalid-cwe")
    assert valid is False
    assert err is not None
