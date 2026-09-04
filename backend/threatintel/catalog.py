from typing import List, Dict, Any

BUILTIN_THREAT_INTEL_CATALOG: List[Dict[str, Any]] = [
    {
        "intel_id": "intel-atlas-001",
        "source": "MITRE_ATLAS",
        "indicator_type": "ATLAS_TECHNIQUE",
        "indicator": "AML.T0054",
        "category": "PROMPT_INJECTION",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "description": "LLM Prompt Injection: Crafting adversarial input to override system instructions and alter model behavior."
    },
    {
        "intel_id": "intel-owasp-001",
        "source": "OWASP_TOP_10_LLM",
        "indicator_type": "OWASP_CATEGORY",
        "indicator": "LLM01",
        "category": "PROMPT_INJECTION",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "description": "OWASP LLM01: Prompt Injection - Manipulating large language model via crafted inputs to execute unauthorized actions."
    },
    {
        "intel_id": "intel-cwe-077",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-77",
        "category": "PROMPT_INJECTION",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection / Prompt Overrides)."
    },
    {
        "intel_id": "intel-atlas-002",
        "source": "MITRE_ATLAS",
        "indicator_type": "ATLAS_TECHNIQUE",
        "indicator": "AML.T0051",
        "category": "SYSTEM_PROMPT_EXTRACTION",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "LLM System Prompt Extraction: Eliciting proprietary system instructions, internal guidelines, or meta-prompts."
    },
    {
        "intel_id": "intel-owasp-007",
        "source": "OWASP_TOP_10_LLM",
        "indicator_type": "OWASP_CATEGORY",
        "indicator": "LLM07",
        "category": "SYSTEM_PROMPT_EXTRACTION",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "OWASP LLM07: System Information Leakage - Disclosure of confidential system prompt instructions."
    },
    {
        "intel_id": "intel-owasp-006",
        "source": "OWASP_TOP_10_LLM",
        "indicator_type": "OWASP_CATEGORY",
        "indicator": "LLM06",
        "category": "SECRET_LEAKAGE",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "description": "OWASP LLM06: Sensitive Information Disclosure - Accidental exposure of credentials, API keys, and sensitive data in LLM responses."
    },
    {
        "intel_id": "intel-cwe-798",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-798",
        "category": "SECRET_LEAKAGE",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "description": "CWE-798: Use of Hard-coded Credentials / Inadvertent Leakage of Secrets."
    },
    {
        "intel_id": "intel-cwe-359",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-359",
        "category": "RESPONSE_PII",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "CWE-359: Exposure of Private Personal Information (PII) to an Unauthorized Actor."
    },
    {
        "intel_id": "intel-cwe-359-in",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-359",
        "category": "INPUT_DLP",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "CWE-359: Ingestion of Unredacted PII / Compliance Breach on Prompt Ingestion."
    },
    {
        "intel_id": "intel-owasp-002",
        "source": "OWASP_TOP_10_LLM",
        "indicator_type": "OWASP_CATEGORY",
        "indicator": "LLM02",
        "category": "UNSAFE_CONTENT",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "OWASP LLM02: Insecure Output Handling - Generating unsafe, malicious, or unverified payload outputs."
    },
    {
        "intel_id": "intel-owasp-004",
        "source": "OWASP_TOP_10_LLM",
        "indicator_type": "OWASP_CATEGORY",
        "indicator": "LLM04",
        "category": "RATE_LIMITING",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "description": "OWASP LLM04: Model Denial of Service - Resource exhaustion through unbounded request floods."
    },
    {
        "intel_id": "intel-cwe-400",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-400",
        "category": "RATE_LIMITING",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "description": "CWE-400: Uncontrolled Resource Consumption."
    },
    {
        "intel_id": "intel-cwe-284",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-284",
        "category": "RBAC",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "CWE-284: Improper Access Control - Unauthorized access to restricted high-tier LLM models."
    },
    {
        "intel_id": "intel-cwe-287",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-287",
        "category": "AUTHENTICATION",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "description": "CWE-287: Improper Authentication - Missing or invalid API key authentication validation."
    },
    {
        "intel_id": "intel-cwe-345",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-345",
        "category": "CACHE_ISOLATION",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "CWE-345: Insufficient Verification of Data Authenticity - Semantic cache poisoning and cross-tenant pollution."
    },
    {
        "intel_id": "intel-cwe-778",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-778",
        "category": "AUDIT",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "description": "CWE-778: Insufficient Logging - Failure to record actionable security metadata and audit trail."
    },
    {
        "intel_id": "intel-atlas-003",
        "source": "MITRE_ATLAS",
        "indicator_type": "ATLAS_TECHNIQUE",
        "indicator": "AML.T0043",
        "category": "JAILBREAK",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "description": "LLM Jailbreak / Craft Adversarial Prompts: Bypassing safety alignment filters using persona adoption or cognitive overload."
    },
    {
        "intel_id": "intel-cwe-863",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-863",
        "category": "POLICY",
        "severity": "HIGH",
        "confidence": 0.90,
        "description": "CWE-863: Incorrect Authorization - Inconsistent enforcement of dynamic security policy versions."
    },
    {
        "intel_id": "intel-cwe-693",
        "source": "NVD_CVE",
        "indicator_type": "CWE",
        "indicator": "CWE-693",
        "category": "OBSERVABILITY",
        "severity": "LOW",
        "confidence": 0.80,
        "description": "CWE-693: Protection Mechanism Failure - Inadequate telemetry or dropped Prometheus/SIEM monitoring metrics."
    }
]
