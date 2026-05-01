# Product Requirements Document: Remediation Twin React + FastAPI

## Product Summary

**Product name:** Remediation Twin

**Category:** Enterprise remediation simulation, orchestration, vulnerability analytics, and agentic governance platform

**Stack:** React, Python FastAPI, MongoDB

**Purpose:** Help enterprises turn security findings into prioritized, simulated, approved, auditable remediation work with vulnerability chaining, attack-path analytics, virtual patching, path breakers, and governed agentic planning.

## Problem Statement

Enterprises have many tools that detect risk but few systems that safely coordinate remediation. Vulnerability scanners, cloud security tools, IAM analyzers, code scanners, Kubernetes platforms, and compliance systems produce overlapping findings. Teams struggle to decide what matters, how vulnerabilities chain together, who owns remediation, what will break if remediated, whether a compensating control is safer, what risk remains after remediation, and what evidence is needed.

## Goals

- Provide a full-stack remediation platform using React, FastAPI, and MongoDB.
- Ingest and normalize findings from multiple enterprise sources.
- Map findings to assets and business context.
- Construct vulnerability chains and attack paths from scanner-normalized inputs.
- Prioritize by technical risk, business risk, path difficulty, and before/after remediation risk.
- Simulate remediation before change.
- Generate rollout, rollback, validation, and evidence plans.
- Route high-risk work through approvals.
- Recommend virtual patches and attack-path breakers.
- Enable agentic planning with any LLM, SLM, model gateway, or deterministic fallback.
- Keep live execution governed and dry-run by default.
- Preserve audit logs and report snapshots.

## Vulnerability Chaining Requirements

| Capability | Requirement |
| --- | --- |
| Scanner normalization | Accept Tenable, Qualys, Wiz, Snyk, GitHub Advanced Security, AWS Security Hub, Kubernetes, IAM, cloud posture, compliance, CSV, and API-style findings through the canonical finding model. |
| Attack-path construction | Build logical paths from exposure, scanner findings, asset context, production/crown-jewel targeting, exploitability, active exploitation, and patch availability. |
| Chain steps | Show source scanner, category, severity, technique, exploit state, active exploitation, patch state, and business risk for every step. |
| Difficulty | Score every path as LOW, MEDIUM, HIGH, or VERY_HIGH. |
| Before/after risk | Show pre-remediation risk, post-remediation residual risk, and expected risk delta. |
| Breakers | Recommend WAF/API gateway virtual patches, microsegmentation, conditional IAM deny, and simulation-backed validation. |
| Evidence | Snapshot attack-path analytics into reports and audit logs. |

Required endpoints:

- `GET /api/attack-paths`
- `POST /api/attack-paths`

Required UI:

- Attack Paths page with path count, critical paths, average before risk, average after risk, difficulty, risk delta, and construction method.

## Functional Requirements

| Area | Requirement |
| --- | --- |
| Tenancy | Resolve tenant through `x-tenant-id`; create default local tenant when missing. |
| Ingestion | Support JSON ingestion and prototype data load. |
| Deduplication | Fingerprint findings by source, title, CVE/control, and asset. |
| Asset mapping | Upsert assets from finding payloads. |
| Risk scoring | Score by severity, exploitability, active exploitation, patch availability, exposure, criticality, and sensitivity. |
| Remediation actions | Create actions for new canonical findings. |
| Simulation | Estimate confidence, risk reduction, operational risk, approval, and rollback need. |
| Planning | Generate rollout, rollback, validation, and evidence steps. |
| Workflow | Create approval workflow items. |
| Virtual patching | Recommend compensating controls for exposed, unpatchable, and high-risk findings. |
| Path breakers | Recommend controls that interrupt reachability to high-value targets. |
| Agentic planning | Build model-agnostic plans with safety rails and deterministic fallback. |
| Policies | Store governance policy records. |
| Reports | Store report snapshots and agent plans. |
| Audit | Record important operational events. |
| Operations | Provide connector and worker dry-run endpoints. |

## Agentic Requirements

The platform must support deterministic fallback planning, OpenAI-compatible model gateways, local SLM endpoints, optional Anthropic and Gemini environment contracts, provider readiness display, no raw secrets in prompts, dry-run execution by default, report persistence, audit logging, and policy-gated execution eligibility.

## API Requirements

- `GET /api/health`
- `GET /api/dashboard`
- `POST /api/ingest/json`
- `POST /api/mock-ingest`
- `GET /api/assets`
- `GET /api/findings`
- `GET /api/attack-paths`
- `POST /api/attack-paths`
- `GET /api/remediation-actions`
- `POST /api/remediation-actions/{id}/simulate`
- `POST /api/remediation-actions/{id}/plan`
- `POST /api/remediation-actions/{id}/workflow`
- `GET /api/virtual-patching`
- `POST /api/virtual-patching`
- `GET /api/agentic`
- `POST /api/agentic`
- `GET /api/policies`
- `GET /api/reports`
- `GET /api/audit`
- `POST /api/connectors/live`
- `POST /api/workers/run`
- `GET /api/observability`

## Data Model

MongoDB collections: `tenants`, `assets`, `findings`, `remediation_actions`, `simulations`, `remediation_plans`, `workflow_items`, `policies`, `report_snapshots`, `connector_runs`, and `audit`.

Indexes include tenant slug uniqueness, tenant asset external ID uniqueness, tenant finding fingerprint uniqueness, tenant finding business risk sort, tenant remediation status lookup, and tenant audit time sort.

## UI Requirements

The React app must include operational pages for Dashboard, Findings, Assets, Attack Paths, Remediation, Virtual Patch, Agentic, Policies, Reports, Audit, and Operations. Actions must call real FastAPI endpoints.

## Security Requirements

- Apply security headers.
- Apply local rate limiting.
- Keep connector execution dry-run by default.
- Avoid raw secret persistence.
- Keep model output advisory.
- Require approvals for production-risk actions.
- Preserve audit records for high-impact events.

## Production Readiness Requirements

Before live enterprise deployment, configure managed MongoDB, external secret manager, enterprise SSO/OIDC, immutable evidence storage, queue-backed workers, OpenTelemetry tracing, alert routing, centralized rate limits, production policy configuration, connector credentials, backup, and recovery.

## Success Metrics

- ingestion success rate
- duplicate reduction
- percent of findings mapped to assets
- critical attack-path reduction
- average before/after path-risk delta
- simulation coverage
- approval coverage
- evidence coverage
- business risk reduction
- virtual patch candidate coverage
- path breaker coverage
- agentic readiness score
- audit completeness

## Roadmap

### Phase 0: Prototype
Mock ingestion, findings dashboard, asset mapping, basic risk scoring, one simulation type, and plan generation.

### Phase 1: Production MVP
Multi-tenant backend, JSON and CSV ingestion, MongoDB persistence, remediation queue, simulation engine v1, approval workflow, evidence and audit trail, attack-path analytics, and agentic planner v1.

### Phase 2: Enterprise Readiness
SSO, advanced RBAC, ServiceNow integration, more scanner integrations, advanced reporting, audit hardening, scale improvements, and more simulation types.

### Phase 3: Automation Expansion
CI/CD execution hooks, Kubernetes rollout automation, cloud remediation automation, IAM policy automation, and risk-based auto-approval policies.

### Phase 4: Autonomous Remediation Governance
Policy-governed automated fixes, continuous simulation, predictive risk modeling, self-updating remediation campaigns, and advanced AI planning and verification.
