import pytest
from dataclasses import dataclass
from backend.reporting.compliance import generate_compliance_mappings, COMPLIANCE_DISCLAIMER


@dataclass
class MockEvidence:
    category: str


def test_compliance_mappings_structure_and_disclaimer():
    evidence = [
        MockEvidence(category="PROMPT_INJECTION"),
        MockEvidence(category="INPUT_DLP"),
        MockEvidence(category="RBAC"),
        MockEvidence(category="SECRET_LEAKAGE")
    ]

    mappings = generate_compliance_mappings(evidence)
    assert len(mappings) > 0

    frameworks = {m.framework for m in mappings}
    assert "OWASP Top 10 (2021)" in frameworks
    assert "OWASP LLM Top 10" in frameworks
    assert "MITRE ATLAS" in frameworks
    assert "NIST AI RMF 1.0" in frameworks

    for m in mappings:
        # Mandatory disclaimer check
        assert m.disclaimer == COMPLIANCE_DISCLAIMER
        assert "certification" not in m.coverage_status.lower()
        assert "compliant" not in m.coverage_status.lower()
        assert "passed audit" not in m.coverage_status.lower()
        assert m.coverage_status in ("Control evidence available", "Not evaluated in this run")
