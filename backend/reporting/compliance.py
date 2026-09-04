from typing import List, Dict, Any
from backend.reporting.models import ComplianceMapping

COMPLIANCE_DISCLAIMER = (
    "Compliance mappings provide security-control evidence and assessment coverage only. "
    "They do not constitute certification, legal compliance, or an independent audit."
)

# Canonical Framework Mappings to Gateway Security Controls
FRAMEWORK_CATALOG: List[Dict[str, Any]] = [
    # 1. OWASP Top 10 (2021)
    {
        "framework": "OWASP Top 10 (2021)",
        "control_id": "A01:2021",
        "control_name": "Broken Access Control",
        "gateway_controls": ["RBAC Allowed Models", "Provider Authorization", "Semantic Cache Tenant Isolation"],
        "tested_categories": ["RBAC", "PROVIDER_AUTHORIZATION", "CACHE_ISOLATION"]
    },
    {
        "framework": "OWASP Top 10 (2021)",
        "control_id": "A02:2021",
        "control_name": "Cryptographic Failures & Secret Exposure",
        "gateway_controls": ["Secret Leakage Protection", "Response PII Sanitization", "Encrypted Cache Storage"],
        "tested_categories": ["SECRET_LEAKAGE", "RESPONSE_PII", "INPUT_DLP"]
    },
    {
        "framework": "OWASP Top 10 (2021)",
        "control_id": "A03:2021",
        "control_name": "Injection & Prompt Manipulation",
        "gateway_controls": ["Prompt Injection Detection", "Jailbreak Detection", "System Prompt Extraction Detection", "Input DLP"],
        "tested_categories": ["PROMPT_INJECTION", "JAILBREAK", "SYSTEM_PROMPT_EXTRACTION", "INPUT_DLP"]
    },
    {
        "framework": "OWASP Top 10 (2021)",
        "control_id": "A04:2021",
        "control_name": "Insecure Design",
        "gateway_controls": ["Dynamic Policy Engine", "Red-Team Validation Engine", "Continuous Campaign Regression Detection"],
        "tested_categories": ["POLICY_ENFORCEMENT", "AUTHENTICATION", "RATE_LIMITING"]
    },
    {
        "framework": "OWASP Top 10 (2021)",
        "control_id": "A05:2021",
        "control_name": "Security Misconfiguration",
        "gateway_controls": ["Safe Mock Provider Defaults", "Rate Limiting", "Provider Health Check"],
        "tested_categories": ["RATE_LIMITING", "PROVIDER_AUTHORIZATION"]
    },
    {
        "framework": "OWASP Top 10 (2021)",
        "control_id": "A07:2021",
        "control_name": "Identification and Authentication Failures",
        "gateway_controls": ["API Key Authentication", "Session Verification", "Rate-Limited Auth Endpoints"],
        "tested_categories": ["AUTHENTICATION", "RBAC"]
    },
    {
        "framework": "OWASP Top 10 (2021)",
        "control_id": "A09:2021",
        "control_name": "Security Logging and Monitoring Failures",
        "gateway_controls": ["Structured Audit Logging", "Prometheus Metrics", "OpenTelemetry Traces", "SIEM Security Events"],
        "tested_categories": ["AUDIT_LOGGING", "OBSERVABILITY"]
    },

    # 2. OWASP LLM Top 10 (2025)
    {
        "framework": "OWASP LLM Top 10",
        "control_id": "LLM01",
        "control_name": "Prompt Injection",
        "gateway_controls": ["Direct & Indirect Prompt Injection Detection", "Recursive Injection Analysis"],
        "tested_categories": ["PROMPT_INJECTION", "JAILBREAK"]
    },
    {
        "framework": "OWASP LLM Top 10",
        "control_id": "LLM02",
        "control_name": "Sensitive Information Disclosure",
        "gateway_controls": ["Input DLP Filter", "Response PII Sanitization", "Secret Leakage Detection"],
        "tested_categories": ["INPUT_DLP", "RESPONSE_PII", "SECRET_LEAKAGE"]
    },
    {
        "framework": "OWASP LLM Top 10",
        "control_id": "LLM04",
        "control_name": "Model Denial of Service",
        "gateway_controls": ["Sliding-Window Rate Limiting", "Redis Semantic Cache", "Strict Request Timeouts"],
        "tested_categories": ["RATE_LIMITING", "CACHE_ISOLATION"]
    },
    {
        "framework": "OWASP LLM Top 10",
        "control_id": "LLM05",
        "control_name": "Improper Output Handling",
        "gateway_controls": ["Response Unsafe Content Filter", "Post-Execution PII Sanitization", "Secret Redaction"],
        "tested_categories": ["UNSAFE_RESPONSE", "RESPONSE_PII", "SECRET_LEAKAGE"]
    },
    {
        "framework": "OWASP LLM Top 10",
        "control_id": "LLM06",
        "control_name": "Excessive Agency",
        "gateway_controls": ["RBAC Model Whitelisting", "Provider Authorization", "Mock-Model Safety Enclave"],
        "tested_categories": ["RBAC", "PROVIDER_AUTHORIZATION"]
    },
    {
        "framework": "OWASP LLM Top 10",
        "control_id": "LLM07",
        "control_name": "System Prompt Leakage",
        "gateway_controls": ["System Prompt Extraction Filter", "Response System Instruction Scrubbing"],
        "tested_categories": ["SYSTEM_PROMPT_EXTRACTION"]
    },
    {
        "framework": "OWASP LLM Top 10",
        "control_id": "LLM10",
        "control_name": "Unbounded Consumption",
        "gateway_controls": ["Role-Based Rate Limiting", "Token Threshold Enforcement"],
        "tested_categories": ["RATE_LIMITING"]
    },

    # 3. MITRE ATLAS
    {
        "framework": "MITRE ATLAS",
        "control_id": "AML.T0051",
        "control_name": "LLM Prompt Injection",
        "gateway_controls": ["Prompt Injection Heuristics", "Adversarial Keyword Filter"],
        "tested_categories": ["PROMPT_INJECTION", "JAILBREAK"]
    },
    {
        "framework": "MITRE ATLAS",
        "control_id": "AML.T0054",
        "control_name": "LLM System Prompt Extraction",
        "gateway_controls": ["Extraction Pattern Detection", "Meta-Prompt Filtering"],
        "tested_categories": ["SYSTEM_PROMPT_EXTRACTION"]
    },
    {
        "framework": "MITRE ATLAS",
        "control_id": "AML.T0048",
        "control_name": "Discover Model Information",
        "gateway_controls": ["Model Whitelisting RBAC", "Provider Privacy Enclave"],
        "tested_categories": ["RBAC", "PROVIDER_AUTHORIZATION"]
    },
    {
        "framework": "MITRE ATLAS",
        "control_id": "AML.T0043",
        "control_name": "Craft Adversarial Data",
        "gateway_controls": ["Red-Team Synthetic Validation Suite", "Regression Detection"],
        "tested_categories": ["PROMPT_INJECTION", "JAILBREAK", "UNSAFE_RESPONSE"]
    },

    # 4. NIST AI RMF 1.0
    {
        "framework": "NIST AI RMF 1.0",
        "control_id": "GOVERN-1.1",
        "control_name": "AI Risk Management Governance",
        "gateway_controls": ["Dynamic Security Policy Engine", "Policy Version Auditing"],
        "tested_categories": ["POLICY_ENFORCEMENT"]
    },
    {
        "framework": "NIST AI RMF 1.0",
        "control_id": "MAP-1.1",
        "control_name": "AI Threat & Context Mapping",
        "gateway_controls": ["14-Category Security Threat Taxonomy", "Adversarial Red-Team Catalog"],
        "tested_categories": ["INPUT_DLP", "PROMPT_INJECTION", "JAILBREAK", "SECRET_LEAKAGE"]
    },
    {
        "framework": "NIST AI RMF 1.0",
        "control_id": "MEASURE-2.1",
        "control_name": "AI Security Evaluation & Measurement",
        "gateway_controls": ["Automated Security Campaigns", "Baseline Comparison Engine", "Regression Detection"],
        "tested_categories": ["OBSERVABILITY", "AUDIT_LOGGING"]
    },
    {
        "framework": "NIST AI RMF 1.0",
        "control_id": "MANAGE-1.1",
        "control_name": "AI Risk Mitigation & Incident Response",
        "gateway_controls": ["Real-time In-Line Blocking", "Response PII Sanitization", "SOC Alert Engine"],
        "tested_categories": ["INPUT_DLP", "UNSAFE_RESPONSE", "RESPONSE_PII", "SECRET_LEAKAGE"]
    }
]


def generate_compliance_mappings(evidence_items: List[Any]) -> List[ComplianceMapping]:
    """
    Generate informational compliance mappings backed by actual security validation evidence.
    """
    # Count evidence items per category
    category_counts: Dict[str, int] = {}
    for ev in evidence_items:
        cat = getattr(ev, "category", "UNKNOWN").upper()
        category_counts[cat] = category_counts.get(cat, 0) + 1

    mappings: List[ComplianceMapping] = []
    for item in FRAMEWORK_CATALOG:
        ev_count = sum(category_counts.get(cat, 0) for cat in item["tested_categories"])
        coverage_status = (
            "Control evidence available" if ev_count > 0
            else "Not evaluated in this run"
        )
        mappings.append(
            ComplianceMapping(
                framework=item["framework"],
                control_id=item["control_id"],
                control_name=item["control_name"],
                gateway_controls=item["gateway_controls"],
                evidence_count=ev_count,
                coverage_status=coverage_status,
                disclaimer=COMPLIANCE_DISCLAIMER
            )
        )
    return mappings
