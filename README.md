# Enterprise LLM & GenAI Security Gateway & SOC Platform

An enterprise-grade, high-performance security gateway, semantic caching platform, and SOC telemetry system for LLM and GenAI applications. It provides end-to-end bidirectional security: API key authentication, **Role-Based Access Control (RBAC)**, Redis rate limiting, Presidio DLP PII redaction, prompt injection & jailbreak defense, Redis Semantic Caching, **Multi-Provider LLM Abstraction (OpenAI, Anthropic Claude, Mock)**, LLM response security & secret leakage protection, persistent PostgreSQL security audit logging, and a **real-time SOC Security Operations Center Dashboard**.

> [!IMPORTANT]
> **Zero-Bypass Security Guarantee**:
> - All security controls (**Authentication, RBAC Model Authorization, Rate Limiting, Input DLP, and Prompt Injection Defense**) occur **BEFORE** cache lookup and provider invocation.
> - No provider (OpenAI, Anthropic Claude, or Mock) ever receives raw PII or uninspected injection payloads.
> - All provider outputs undergo strict response security inspection (Secret leakage, Unsafe code, and PII sanitization) before client delivery or caching.

---

## 🏛️ End-to-End System Architecture

```text
                           USERS / CLIENTS
                                 │
                                 ▼
                          ┌─────────────┐
                          │ AI SECURITY │
                          │   GATEWAY   │
                          └──────┬──────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
   API Key Auth          Redis Rate Limit       Presidio Input DLP
(X-API-Key Header)     (10 req/min, 60s TTL)   (PII Detection & Masking)
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                     Role-Based Access Control
                      (RBAC Model Authorization)
                     ┌───────────┴───────────┐
                     ▼                       ▼
                 [ ALLOW ]               [ DENY ]
                     │                   (HTTP 403)
                     ▼                       │
          Prompt Injection Defense           │
     (Jailbreaks, Overrides, Obfuscation)    │
                     │                       │
           ┌─────────┴─────────┐             │
           ▼                   ▼             │
       [ ALLOW ]           [ BLOCK ]         │
           │               (HTTP 403)        │
           ▼                   │             │
   🧠 REDIS SEMANTIC CACHE     │             │
   (Normalized Prompt Lookup)  │             │
     ┌─────┴─────┐             │             │
 HIT │           │ MISS        │             │
     │           ▼             │             │
     │   MULTI-PROVIDER LAYER  │             │
     │   ┌───────┼─────────┐   │             │
     │   ▼       ▼         ▼   │             │
     │  Mock   OpenAI   Claude │             │
     │   │       │         │   │             │
     │   └───────┼─────────┘   │             │
     │           ▼             │             │
     │ Response Security Filter│             │
     │(PII, Secrets, Malware)  │             │
     │   ┌───────┴───────┐     │             │
     │   ▼               ▼     │             │
     │ [ ALLOW ]     [ BLOCK ] │             │
     │   │          (HTTP 403) │             │
     │   ▼               │     │             │
     │ Write to Cache    │     │             │
     │   │               │     │             │
     └───┴───────┬───────┴─────┴─────────────┘
                 ▼
      PostgreSQL Audit Trail
     (Metadata-only Logging)
                 │
       ┌─────────┴─────────┐
       ▼                   ▼
 Chat Response     SOC Dashboard API (/api/dashboard/*)
                           │
                           ▼
               ┌───────────────────────┐
               │ SOC DASHBOARD (React) │
               │  - Real-time KPIs     │
               │  - Threat Overview    │
               │  - Multi-Provider Ops │
               │  - Cache Performance  │
               │  - Policy Management  │
               │  - Observability      │
               └───────────────────────┘
```

---

## 🛡️ Centralized Security Policy Engine & Dynamic Management

The gateway utilizes a centralized, versioned, auditable Policy Engine that controls security thresholds, rate limits, model permissions, and caching dynamically without hardcoded constants or service restarts.

```text
                 ┌─────────────────────┐
                 │ Security Policy DB  │
                 │    PostgreSQL       │
                 └──────────┬──────────┘
                            │
                            ▼
                    Policy Service
                            │
                     ┌──────┴──────┐
                     │ Redis Cache │ (TTL: 60s)
                     └──────┬──────┘
                            │
                            ▼
                    Policy Engine
                            │
       ┌────────────────────┼───────────────────┐
       ▼                    ▼                   ▼
      RBAC             Input Security      Response Security
 (Model Allowlists) (DLP & Injections)    (Output Filtering)
       │                    │                   │
       └────────────────────┼───────────────────┘
                            ▼
                     Security Decision
```

### Policy Schema (`SecurityPolicySchema`)

```json
{
  "policy_version": "1.0.0",
  "rate_limit": {
    "requests": 10,
    "window_seconds": 60
  },
  "input_security": {
    "dlp_enabled": true,
    "prompt_injection_enabled": true,
    "block_threshold": 60
  },
  "response_security": {
    "enabled": true,
    "block_threshold": 80,
    "sanitize_threshold": 30
  },
  "cache": {
    "enabled": true,
    "ttl_seconds": 300
  },
  "rbac": {
    "admin": {
      "allowed_models": ["mock-model", "gpt-4o-mini", "gpt-4", "gpt-4o", "claude-3-5-sonnet-latest"],
      "dashboard_access": true
    },
    "analyst": {
      "allowed_models": ["mock-model", "gpt-4o-mini", "claude-3-5-sonnet-latest"],
      "dashboard_access": true
    },
    "developer": {
      "allowed_models": ["mock-model"],
      "dashboard_access": false
    }
  },
  "providers": {
    "mock": { "enabled": true, "allowed_models": ["mock-model"], "timeout_seconds": 30 },
    "openai": { "enabled": true, "allowed_models": ["gpt-4o-mini", "gpt-4", "gpt-4o"], "timeout_seconds": 30 },
    "anthropic": { "enabled": true, "allowed_models": ["claude-3-5-sonnet-latest"], "timeout_seconds": 30 }
  }
}
```

### Security Policy APIs

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/api/policies/active` | `GET` | Admin, Analyst | Retrieve currently active security policy schema and metadata. |
| `/api/policies/history` | `GET` | Admin, Analyst | Retrieve audit history of all policy versions and activation timestamps. |
| `/api/policies/validate` | `POST` | Admin, Analyst | Dry-run validation of a policy JSON against schema guardrails without persisting. |
| `/api/policies` | `POST` | Admin Only | Create and store a new versioned security policy. |
| `/api/policies/{version}/activate` | `POST` / `PUT` | Admin Only | Transactionally activate or rollback to a policy version, invalidating Redis cache. |

---

## 🔭 Enterprise Observability & SIEM Telemetry

Standard Prometheus metrics exposed at `/metrics`:
- `gateway_requests_total`, `gateway_request_duration_seconds`
- `gateway_blocked_requests_total`, `gateway_pii_detections_total`, `gateway_prompt_injection_total`
- `gateway_response_blocks_total`, `gateway_secret_leakage_total`, `gateway_unsafe_content_total`
- `gateway_policy_evaluations_total`, `gateway_policy_fallback_total`, `gateway_policy_activation_total`
- `gateway_provider_requests_total`, `gateway_cache_hits_total`

Structured JSON logs and OpenTelemetry distributed spans (`security.policy`, `security.authentication`, `security.rbac`, `security.rate_limit`, `security.input_dlp`, `security.prompt_injection`, `cache.lookup`, `provider.generate`, `security.response_filter`, `audit.persist`).

---

## 🧪 Automated Security Validation & Red-Team Testing Engine

An integrated, defensive automated security validation engine (`backend/redteam/`) that continuously tests and verifies gateway controls against synthetic adversarial attack patterns across 14 deterministic categories.

```text
                  Security Validation Engine
                             │
                             ▼
                     Controlled Test Catalog
                             │
                             ▼
                       Test Runner
                             │
                             ▼
                      Local Gateway
                             │
             ┌───────────────┼───────────────┐
             ▼               ▼               ▼
           PASS            FAIL            ERROR
             │               │               │
             └───────────────┼───────────────┘
                             ▼
                     Result Persistence
                             │
                 ┌───────────┼───────────┐
                 ▼           ▼           ▼
               SOC        SIEM        Metrics
             Dashboard    Events      Prometheus
```

### Key Capabilities & Safety Controls
- **Zero External API Cost**: Strictly defaults to the deterministic in-process `mock-model`. External OpenAI or Claude providers are never contacted during normal testing.
- **Safe Synthetic Payloads**: All test vectors utilize safe, synthetic data (`test.user@example.com`, `+1 555-019-2834`, fake AWS keys). Real credentials and real personal data are strictly prohibited.
- **Defensive QA Scope**: Tests local gateway controls only (No network scanning, credential stuffing, or destructive attacks).
- **14 Test Categories**:
  - `AUTHENTICATION`: Missing, invalid, and valid API key evaluation.
  - `RBAC`: Role-based model restrictions (e.g. Developer -> `gpt-4o` 403) and dashboard access controls.
  - `RATE_LIMITING`: Controlled low-rate validation (3 allowed -> 4th HTTP 429).
  - `INPUT_DLP`: Synthetic Presidio redaction and raw PII leak prevention.
  - `PROMPT_INJECTION`: Instruction overrides and adversarial rule bypass detection.
  - `JAILBREAK`: Unrestricted assistant persona and safety disable attempts.
  - `SYSTEM_PROMPT_EXTRACTION`: Hidden developer prompt dump detection.
  - `SECRET_LEAKAGE`: Output filter detection for fake AWS/OpenAI keys.
  - `UNSAFE_CONTENT`: Output filter detection for malicious reverse shells/exploits.
  - `RESPONSE_PII`: Output filter PII sanitization.
  - `CACHE_ISOLATION`: Role, model, and provider cache partition verification.
  - `POLICY`: Active policy versioning and threshold evaluation.
  - `AUDIT`: SIEM audit trail verification without raw sensitive payloads.
  - `OBSERVABILITY`: Prometheus telemetry export and trace span validation.

### CLI Usage
```bash
# Run full 14-category validation suite
python -m backend.redteam.cli

# Filter by specific category
python -m backend.redteam.cli --category PROMPT_INJECTION
python -m backend.redteam.cli --category INPUT_DLP
```

### API Endpoints (Admin & Analyst RBAC)
- `POST /api/security-tests/run`: Trigger validation suite (Developer denied with HTTP 403)
- `GET /api/security-tests/runs`: List historical validation runs
- `GET /api/security-tests/runs/{run_id}`: Retrieve run status and security score
- `GET /api/security-tests/runs/{run_id}/report`: Full normalized security report
- `GET /api/security-tests/findings`: Triage active security findings
- `GET /api/security-tests/catalog`: Server-controlled test catalog metadata

---

## 📊 Security Assessment Campaigns, Baseline Comparison & Regression Engine

Continuous assessment layer (`backend/campaign/` and `backend/services/campaign_service.py`) that executes validation suites against established baselines, performs individual `test_id` result comparisons, tracks delta score drift, and detects security regressions.

```text
       ┌────────────────────────┐
       │   Assessment Campaign  │
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │  Execute Test Runner   │
       │    (mock-model safe)   │
       └───────────┬────────────┘
                   │
                   ▼
     ┌────────────────────────────┐
     │  Individual test_id Match  │
     │  Baseline vs Current Run   │
     └─────────────┬──────────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
    [ PASS → PASS ]     [ PASS → FAIL ]
       No Drift            REGRESSION!
         │                   │
         │                   ▼
         │           Create Regression Item
         │           Emit SIEM Security Event
         │           Increment Prometheus Metric
         │                   │
         └─────────┬─────────┘
                   ▼
         Campaign Run Summary
           - Baseline Score
           - Current Score
           - Score Delta
           - Regressions Detected
```

### Campaign API Endpoints (Admin & Analyst RBAC)
- `POST /api/campaigns`: Create assessment campaign (Developer denied with HTTP 403)
- `GET /api/campaigns`: List campaigns
- `GET /api/campaigns/{campaign_id}`: Get campaign details and latest metrics
- `PUT /api/campaigns/{campaign_id}`: Update campaign configuration
- `POST /api/campaigns/{campaign_id}/execute`: Trigger campaign execution, run comparison, and detect regressions
- `GET /api/campaigns/{campaign_id}/runs`: List campaign run history
- `GET /api/campaigns/{campaign_id}/regressions`: List recorded security regressions
- `POST /api/campaigns/{campaign_id}/baseline`: Explicitly set or update reference baseline run
- `POST /api/campaigns/{campaign_id}/pause`: Pause campaign
- `POST /api/campaigns/{campaign_id}/resume`: Resume campaign
- `POST /api/campaigns/{campaign_id}/archive`: Archive campaign

---

## ⏰ Step 17 — Continuous Security Posture, Automated Campaign Scheduling & SOC Alerting

### Continuous Assessment Architecture
1. **Automated Scheduler Worker**: Periodic background polling (`SCHEDULER_POLL_INTERVAL_SECONDS`, default 30s) executing due campaign schedules safely without external API calls or shell execution.
2. **Frequency Safety Enforcement**: All recurring schedules (`INTERVAL` and `CRON`) MUST have an execution frequency of $\ge 60$ minutes. High-frequency or uncontrolled cron expressions (e.g. `* * * * *`, `*/5 * * * *`, `*/30 * * * *`) are rejected with HTTP 400.
3. **Unified Distributed Concurrency Locking**: Both automated scheduled executions and manual triggers acquire the exact same atomic Redis key: `security_campaign:lock:<campaign_id>` with automatic TTL timeout to prevent race conditions and duplicate executions.
4. **Actionable SOC Alert Engine**:
   - `CAMPAIGN_REGRESSION`: Fired when an individual security control previously passing regresses to failure.
   - `SECURITY_SCORE_DEGRADATION`: Fired when overall security score drops by $\ge 5\%$.
   - `CAMPAIGN_EXECUTION_ERROR` & `SCHEDULER_ERROR`: Infrastructure and execution failure alerting.
   - **Deterministic Alert Deduplication**: Evaluates state against active open alerts to eliminate alert storms.
5. **Continuous Security Posture API**: `GET /api/dashboard/security-posture` evaluates live gateway health (`SECURE` $\ge 90\%$, `DEGRADED` $70\text{--}89\%$, `CRITICAL` $<70\%$ or open critical alerts).

### Scheduler & Alert API Reference
- `POST /api/scheduler/campaigns/{campaign_id}`: Create recurring schedule (Admin/Analyst)
- `GET /api/scheduler/campaigns`: List configured campaign schedules
- `GET /api/scheduler/campaigns/{campaign_id}`: Get schedule details
- `PUT /api/scheduler/campaigns/{campaign_id}`: Update schedule parameters
- `POST /api/scheduler/campaigns/{campaign_id}/enable`: Enable schedule
- `POST /api/scheduler/campaigns/{campaign_id}/disable`: Disable schedule
- `DELETE /api/scheduler/campaigns/{campaign_id}`: Delete schedule
- `GET /api/scheduler/status`: Overall scheduler worker status
- `GET /api/scheduler/next-runs`: List upcoming execution estimates
- `POST /api/scheduler/campaigns/{campaign_id}/trigger`: Trigger immediate scheduled campaign execution
- `GET /api/alerts`: List alerts with optional status/severity filters
- `GET /api/alerts/summary`: Alert metrics by severity and status
- `GET /api/alerts/open`: Active open SOC alerts
- `POST /api/alerts/{alert_id}/acknowledge`: Acknowledge security alert
- `POST /api/alerts/{alert_id}/resolve`: Mark security alert resolved
- `GET /api/dashboard/security-posture`: Real-time continuous security posture status

### Step 19 Incident Management & Investigation Endpoints
- `POST /api/incidents`: Create security incident (Admin/Analyst)
- `GET /api/incidents`: List incidents with status/severity filters
- `GET /api/incidents/summary`: Summary incident statistics & average risk score
- `GET /api/incidents/{incident_id}`: Deep incident investigation bundle (Timeline, Evidence, Notes, Actions, Alerts, Campaigns, Findings)
- `PUT /api/incidents/{incident_id}`: Update incident metadata
- `POST /api/incidents/{incident_id}/assign`: Assign incident to analyst
- `POST /api/incidents/{incident_id}/status`: Transition incident status (OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE)
- `POST /api/incidents/{incident_id}/notes`: Add sanitized analyst observation note
- `GET /api/incidents/{incident_id}/timeline`: Retrieve unified chronological timeline
- `GET /api/incidents/{incident_id}/evidence`: Retrieve attached evidence artifacts
- `POST /api/incidents/{incident_id}/evidence`: Attach cryptographic SHA-256 evidence
- `POST /api/incidents/{incident_id}/reports`: Link Step 18 security assessment report
- `GET /api/incidents/{incident_id}/reports`: List linked reports
- `POST /api/incidents/{incident_id}/actions`: Record controlled SOC response action
- `POST /api/incidents/{incident_id}/resolve`: Mark incident resolved
- `POST /api/incidents/{incident_id}/false-positive`: Mark incident false positive

---

## 🛡️ Step 19 — Security Incident Investigation, Case Management & SOC Response

The gateway provides a unified, deterministic, metadata-only Incident Investigation and Case Management system connecting automated security tests, campaign runs, regressions, SOC alerts, evidence artifacts, and controlled response workflows.

```text
Security Tests ──► Campaigns ──► Regressions ──► SOC Alerts ──► Security Incidents ──► Investigation & Controlled Response
```

### Safety & Reliability Guarantees
1. **Non-Blocking & Fail-Safe Correlation**: Incident correlation is an observability layer. Any correlation failure is caught in isolated exception handling, logs `SECURITY_INCIDENT_CORRELATION_ERROR`, increments `gateway_incident_correlation_errors_total`, and leaves the underlying alert and security pipeline completely intact.
2. **Deterministic Risk Scoring (0–100)**:
   - CRITICAL finding: `+40`
   - HIGH finding: `+25`
   - MEDIUM finding: `+10`
   - LOW finding: `+5`
   - Regression detected: `+15`
   - Posture degraded: `+15`
   - Repeated event: `+10`
   - Multiple domains (2+ categories): `+10`
   - Clamped to 0–100 (`LOW` 0–29, `MEDIUM` 30–59, `HIGH` 60–79, `CRITICAL` 80–100).
3. **Controlled Non-Destructive Response Actions**:
   - Supported: `ACKNOWLEDGE_ALERT`, `ASSIGN_INCIDENT`, `CHANGE_STATUS`, `MARK_FALSE_POSITIVE`, `ATTACH_EVIDENCE`, `ATTACH_REPORT`, `REQUEST_POLICY_REVIEW`.
   - > **SOC Invariant**: Incident response actions are controlled, auditable workflows. The platform does not autonomously disable security controls or perform destructive remediation.
4. **Strict Sanitization**: All incident notes, evidence, timeline events, and descriptions are scrubbed to prevent exposure of API keys, passwords, bearer tokens, JWTs, raw prompts, raw model responses, or PII.

---

### Step 20 Threat Intelligence, Attack Surface & Control Coverage Endpoints
- `POST /api/assets`: Register AI/LLM asset or gateway component (Admin/Analyst)
- `GET /api/assets`: List inventoried assets with filters
- `GET /api/assets/summary`: Aggregated asset counts & average risk score
- `GET /api/assets/attack-surface`: Logical attack surface dataflow graph
- `GET /api/assets/{asset_id}`: Asset details
- `PUT /api/assets/{asset_id}`: Update asset metadata/criticality
- `GET /api/assets/{asset_id}/coverage`: Multidimensional asset test and control coverage
- `GET /api/controls`: List inventoried security controls
- `GET /api/controls/{control_id}`: Control details
- `GET /api/controls/coverage`: Overall control coverage percentage and matrix
- `GET /api/controls/gaps`: Detected security control gaps with recommendations
- `POST /api/threat-intelligence`: Ingest threat intelligence indicator
- `GET /api/threat-intelligence`: List threat intelligence indicators
- `GET /api/threat-intelligence/summary`: Threat intelligence summary statistics
- `GET /api/threat-intelligence/{intel_id}`: Threat intelligence indicator detail
- `POST /api/threat-intelligence/match`: Deterministic threat intelligence matcher
- `POST /api/exposures`: Create security exposure entry
- `GET /api/exposures`: List security exposures with filters
- `GET /api/exposures/summary`: Enterprise exposure summary & risk score (0-100)
- `GET /api/exposures/{exposure_id}`: Exposure details
- `POST /api/exposures/{exposure_id}/resolve`: Mark security exposure resolved
- `GET /api/governance/summary`: Unified enterprise governance telemetry summary
- `GET /api/governance/risk`: Deterministic governance risk score (0-100) & factor breakdown
- `GET /api/governance/controls`: Continuous control assurance evaluation matrix
- `GET /api/governance/controls/{control_id}`: Control assurance details for specific control
- `POST /api/governance/assurance/run`: Trigger continuous control assurance evaluation
- `POST /api/governance/exceptions`: Create a security risk exception request
- `GET /api/governance/exceptions`: List security risk exceptions with status/severity filters
- `GET /api/governance/exceptions/overdue`: List overdue security risk exceptions
- `GET /api/governance/exceptions/{exception_id}`: Get risk exception details
- `PUT /api/governance/exceptions/{exception_id}`: Update draft risk exception
- `POST /api/governance/exceptions/{exception_id}/submit`: Submit risk exception for approval
- `POST /api/governance/exceptions/{exception_id}/approve`: Approve risk exception
- `POST /api/governance/exceptions/{exception_id}/reject`: Reject risk exception
- `POST /api/governance/exceptions/{exception_id}/renew`: Renew risk exception with new expiry
- `POST /api/governance/exceptions/{exception_id}/revoke`: Revoke approved risk exception
- `POST /api/governance/exceptions/{exception_id}/close`: Close risk exception upon remediation
- `POST /api/governance/reviews`: Conduct periodic or triggered security governance review
- `GET /api/governance/reviews`: List governance reviews
- `GET /api/governance/reviews/{review_id}`: Get governance review detail
- `GET /api/governance/events`: Query immutable security governance audit events

---

## 🛡️ Step 21 — Security Governance, Risk Acceptance & Continuous Control Assurance

The gateway provides a production-grade governance and risk acceptance layer that translates technical security findings into governed, auditable business decisions:

```text
Threats / Gaps / Incidents ──► Control Assurance ──► Risk Exceptions ──► Governance Reviews ──► Governance Risk Posture
```

### Core Architectural Invariants:
1. **Zero Security Control Bypass**: Accepting a risk exception records a business decision but **never** disables or bypasses DLP redaction, RBAC enforcement, rate limiting, prompt injection defense, or audit logging.
2. **Deterministic Governance Risk Engine (0–100)**:
   $$\text{Risk} = \sum (\text{Critical Exposures} \times 25 + \text{High Exposures} \times 15 + \text{Critical Incidents} \times 20 + \text{High Incidents} \times 10 + \text{Control Gaps} \times 15 + \text{Active Regressions} \times 10 + \text{Overdue Exceptions} \times 15 + \text{Multiple Domains} \times 10 + \text{Threat Intel Matches} \times 10)$$
   - Clamped to $0–100$ (`LOW` 0–29, `MEDIUM` 30–59, `HIGH` 60–79, `CRITICAL` 80–100).
3. **Mandatory Expiration for Risk Exceptions**: Permanent risk acceptance is strictly forbidden. Every exception requires an owner, business justification, and future `expires_at` timestamp. Overdue exceptions are continuously tracked and trigger governance risk penalties and SOC alerts.
4. **Continuous Control Assurance Matrix**: Automatically aggregates test pass rates, active regressions, open incidents, and exposure gaps across 14 security control domains.
5. **Periodic Governance Reviews**: Supports formal reviews (`CONTROL_EFFECTIVENESS`, `RISK_EXCEPTION_REVIEW`, `EXPOSURE_REVIEW`, `INCIDENT_REVIEW`, `EXECUTIVE_SECURITY_REVIEW`) with executive summaries and compliance scores.
6. **Immutable Audit Trail**: All exception state transitions and governance reviews generate immutable audit events (`security_governance_events`) with strict SIEM structured logging and Prometheus metrics.

---

## ☸️ Kubernetes Deployment

```bash
# Validate and deploy via Kustomize
kubectl kustomize k8s/
kubectl kustomize k8s/observability/
kubectl apply -k k8s/
```

Manifests in `k8s/` include:
- `namespace.yaml`, `configmap.yaml`, `secret.example.yaml`
- `postgres.yaml` (StatefulSet, 5Gi PVC), `redis.yaml` (Deployment, 1Gi PVC)
- `backend.yaml` (2 replicas, HPA, PDB, Prometheus annotations), `frontend.yaml` (2 replicas, Nginx SPA)
- `ingress.yaml` (`security-gateway.local`), `network-policy.yaml` (strict zero-trust)
- `observability/` (optional Prometheus & OTel Collector)

---

## 🐳 Docker Compose Stack (Local Single-Node)

```bash
# Build and start all 4 core services
docker compose up -d --build

# Optional Observability profile
docker compose --profile observability up -d
```

---

## 🧪 Testing & Verification

```bash
# Run all 284 automated backend tests
./venv/bin/pytest backend/tests/ -v

# Build frontend SPA
npm --prefix frontend run build

# Run Red-Team CLI validation
./venv/bin/python -m backend.redteam.cli
```





