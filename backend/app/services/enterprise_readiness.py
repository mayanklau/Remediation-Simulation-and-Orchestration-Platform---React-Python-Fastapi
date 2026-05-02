from typing import Any, Literal

ReadinessStatus = Literal["implemented", "contract_ready", "external_setup_required"]


def _control(control_id: str, name: str, status: ReadinessStatus) -> dict[str, str]:
    evidence = {
        "implemented": "Implemented in application logic and covered by current tests/builds.",
        "contract_ready": "Application contract exists; wire customer-specific external systems and credentials.",
        "external_setup_required": "Requires customer infrastructure, cloud account, regional deployment, or security service configuration.",
    }[status]
    return {"id": control_id, "name": name, "status": status, "evidence": evidence}


ENTERPRISE_READINESS_CATALOG: list[dict[str, Any]] = [
    {"id": "identity_access_tenancy", "name": "Identity, Access, And Tenancy", "owner": "security-platform", "controls": [
        _control("oidc_sso", "OIDC, SAML, Azure AD, Okta, Google Workspace, generic IdP contract", "contract_ready"),
        _control("scim_lifecycle", "SCIM provisioning, user lifecycle, group-to-role mapping", "contract_ready"),
        _control("tenant_rbac", "Tenant isolation, cross-tenant denial tests, RBAC on APIs/routes/buttons/service accounts/API keys", "implemented"),
        _control("session_support", "Session expiry, renewal, refresh-token strategy, break-glass audit, support impersonation controls", "contract_ready"),
    ]},
    {"id": "secrets_credentials", "name": "Secrets And Credentials", "owner": "platform-security", "controls": [
        _control("secret_references", "Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager references", "contract_ready"),
        _control("no_raw_secrets", "No raw secret storage, masked display, secret access audit", "implemented"),
        _control("credential_lifecycle", "Validation, rotation, expiry, OAuth refresh, connector health checks", "contract_ready"),
        _control("customer_keys", "Customer-managed keys, BYOK, field-level encryption, encryption at rest and transit", "external_setup_required"),
    ]},
    {"id": "connectors_integrations", "name": "Connectors And Integrations", "owner": "integration-engineering", "controls": [
        _control("manual_connector_builder", "Manual/custom HTTP connector builder, dry-run/live modes, health and run history", "implemented"),
        _control("connector_runtime", "Retries, backoff, dead-letter queues, sync scheduler, trust/data-quality scores", "contract_ready"),
        _control("scanner_cloud_edr", "Tenable, Qualys, Rapid7, Wiz, Prisma Cloud, Lacework, Snyk, GHAS, GitLab, AWS, GCP, Azure, Defender, CrowdStrike, SentinelOne", "contract_ready"),
        _control("work_management", "ServiceNow, Jira, GitHub Issues, Azure DevOps, Slack, Teams, Email, CMDB, CAB calendar", "contract_ready"),
        _control("webhook_sdk", "Webhook signatures, mapping UI, normalization contracts, connector marketplace and parser SDK", "contract_ready"),
    ]},
    {"id": "ingestion_normalization_quality", "name": "Ingestion, Normalization, And Data Quality", "owner": "data-platform", "controls": [
        _control("ingestion_modes", "JSON, CSV, API, webhook, batch, streaming ingestion", "implemented"),
        _control("mapping_lineage", "CSV/API mapping, normalization, canonical mapping, dedup explainability, finding lineage", "contract_ready"),
        _control("data_quality", "Freshness, missing-field detection, confidence scoring, source quality dashboards", "contract_ready"),
        _control("asset_context", "Asset resolution, merge/conflict workflow, ownership disputes, CMDB/cloud/Kubernetes/code/IAM enrichment, business-service/crown-jewel/exposure tagging", "contract_ready"),
    ]},
    {"id": "vulnerability_attack_paths", "name": "Vulnerability Analytics And Attack Paths", "owner": "exposure-management", "controls": [
        _control("domain_chaining", "Network, IAM, cloud, Kubernetes, app, CI/CD, secrets, data-store chaining", "implemented"),
        _control("graph_algorithms", "Attack graph, shortest path, k-hop blast radius, reachability, choke points, centrality", "implemented"),
        _control("preconditions", "Privilege, network access, user interaction, token scope, lateral movement, exploit availability", "implemented"),
        _control("threat_intel", "EPSS, CISA KEV, threat intel, active exploitation enrichment", "contract_ready"),
        _control("risk_quantification", "Difficulty, explainability, confidence, before/after risk, residual risk, FAIR-style risk dollars", "contract_ready"),
    ]},
    {"id": "simulation_decisioning", "name": "Simulation And Decisioning", "owner": "remediation-governance", "controls": [
        _control("control_simulation", "Patch, WAF, API gateway, IAM deny, segmentation, containers, Kubernetes, cloud policy simulation", "implemented"),
        _control("risk_scoring", "Change, operational, rollback, approval, confidence, assumptions, evidence scoring", "implemented"),
        _control("path_breakers", "Path-breaker recommendation, ROI, virtual patching, compensating controls, policy simulation", "implemented"),
        _control("rollout_simulation", "Auto-approval, risk acceptance, progressive rollout, canary remediation", "contract_ready"),
    ]},
    {"id": "remediation_orchestration", "name": "Remediation Orchestration", "owner": "security-operations", "controls": [
        _control("queue_playbooks", "Queue, generated actions, playbooks, golden paths, owners, SLAs", "implemented"),
        _control("campaigns", "Campaigns, blockers, waves, SLA breaches, risk reduction, freeze/maintenance windows", "implemented"),
        _control("approval_exception", "CAB, service owner, security approvals, risk acceptance, exceptions, expiry, renewal", "implemented"),
        _control("execution_hooks", "Dry-run/live execution, CI/CD, Kubernetes, cloud, IAM, Terraform, OPA/Rego, rollback, validation", "contract_ready"),
    ]},
    {"id": "ai_agentic_governance", "name": "AI And Agentic Governance", "owner": "ai-risk", "controls": [
        _control("model_routing", "LLM, SLM, local model, enterprise gateway, deterministic fallback, provider config", "implemented"),
        _control("agent_safety", "Prompt/tool registry, dry-run mode, human approval, recommendation audit, confidence", "implemented"),
        _control("model_risk", "Reasoning trace, decision record, policy simulator, eval harness, hallucination guardrails", "contract_ready"),
        _control("prompt_security", "Prompt injection defenses, sensitive-data redaction, no secrets in prompts, connector-content sanitization", "contract_ready"),
    ]},
    {"id": "evidence_audit_compliance", "name": "Evidence, Audit, And Compliance", "owner": "grc", "controls": [
        _control("audit_evidence", "Full audit trail, immutable option, correlation IDs, evidence packs, chain of custody", "implemented"),
        _control("evidence_exports", "Hash sealing, PDF/JSON/ZIP export, notarization, signed attestations", "contract_ready"),
        _control("evidence_lifecycle", "Before state, simulation, approval, execution, validation, residual risk, legal hold, retention", "implemented"),
        _control("compliance_mapping", "SOC 2, ISO 27001, NIST CSF, PCI DSS, HIPAA, FedRAMP-ready controls, DORA metrics", "contract_ready"),
    ]},
    {"id": "reporting_executive", "name": "Reporting And Executive Views", "owner": "security-leadership", "controls": [
        _control("dashboards", "Executive, CISO, service-owner, engineering, audit, connector, queue, production health dashboards", "implemented"),
        _control("risk_reports", "Business-service, crown-jewel, attack-path closure, weekly risk reduction, blockers, SLA, exceptions", "implemented"),
        _control("exports_telemetry", "Board export, evidence readiness, customer success telemetry, adoption analytics, release notes, mobile view", "contract_ready"),
    ]},
    {"id": "platform_architecture", "name": "Platform Architecture", "owner": "architecture", "controls": [
        _control("contracts", "Services, repositories, DTOs, validation, OpenAPI, versioning, generated clients", "implemented"),
        _control("workers_scale", "Workers, queues, retries, idempotency, transactions, cache, migrations, index checks", "contract_ready"),
        _control("resilience", "Backups, restores, fixtures, multi-tenant data strategy, data residency, regional isolation", "contract_ready"),
        _control("deployment_modes", "Multi-region, active-active, DR, RPO/RTO, air-gapped, on-prem, PrivateLink", "external_setup_required"),
    ]},
    {"id": "security_hardening", "name": "Security Hardening", "owner": "appsec", "controls": [
        _control("api_security", "Rate limits, payload limits, CORS allowlist, CSRF where needed, headers, validation, encoding", "implemented"),
        _control("runtime_security", "SSRF protection, upload validation, webhook signatures, prompt-injection protection", "contract_ready"),
        _control("supply_chain", "Dependency, secret, SAST, DAST, container, SBOM, license scans, non-root containers", "contract_ready"),
        _control("kubernetes_security", "Least privilege, network policies, security contexts, admission policies, disclosure policy", "external_setup_required"),
    ]},
    {"id": "observability_operations", "name": "Observability And Operations", "owner": "sre", "controls": [
        _control("telemetry", "Structured logs, request/correlation IDs, metrics, traces, errors, alerts, SLOs, SLIs", "implemented"),
        _control("runtime_monitoring", "Synthetic monitoring, queue depth, connector failures, simulation duration, risk latency, worker/database health", "contract_ready"),
        _control("operability", "Health/readiness/liveness probes, graceful shutdown, incident/DR runbooks, diagnostics, admin console", "contract_ready"),
        _control("release_ops", "Feature flags, dark launches, release rollback, change logs, customer-facing status", "contract_ready"),
    ]},
    {"id": "testing_quality", "name": "Testing And Quality Gates", "owner": "quality-engineering", "controls": [
        _control("test_pyramid", "Unit, API, integration, database, tenant, RBAC, connector, worker, queue, frontend tests", "implemented"),
        _control("advanced_tests", "E2E, accessibility, visual regression, performance, load, chaos, failover, backup/restore", "contract_ready"),
        _control("contract_security_tests", "Migration, OpenAPI, security, AI eval, prompt injection, preview/staging/prod checks", "contract_ready"),
        _control("ci_gates", "Lint, typecheck, tests, build, dependency, container, SBOM gates", "implemented"),
    ]},
    {"id": "deployment_devops", "name": "Deployment And DevOps", "owner": "devops", "controls": [
        _control("packaging", "Docker Compose, production Dockerfiles, Kubernetes manifests, Helm, Terraform, cloud examples", "contract_ready"),
        _control("environments", "Local, dev, staging, production, config validation, strict production checks, CI/CD, previews", "implemented"),
        _control("deployment_patterns", "Blue/green, canary, rollback, migration pipeline, secret injection, scaling guides, DR guide", "contract_ready"),
    ]},
    {"id": "product_experience", "name": "Product Experience", "owner": "product-design", "controls": [
        _control("onboarding", "Guided first run, admin/tenant/connector onboarding, empty/loading/error states, disabled reasons", "implemented"),
        _control("productivity", "Bulk actions, saved filters, advanced search, graph filters/zoom/minimap/export/drill-down", "implemented"),
        _control("exports_notifications", "CSV/PDF/JSON export, email/Slack/Teams/webhooks, preferences, feedback, in-product docs", "contract_ready"),
        _control("readiness_guides", "Demo separation, customer pilot, go-live, production readiness checklists", "implemented"),
    ]},
    {"id": "commercial_packaging", "name": "Commercial And Packaging", "owner": "product-operations", "controls": [
        _control("editions", "Edition gating, license enforcement, usage metering, tenant/connector/model metrics", "contract_ready"),
        _control("marketplace", "Marketplace packaging, plugin packaging, self-service onboarding, support access controls", "contract_ready"),
        _control("customer_health", "Secure support bundle, adoption telemetry, health score, trial and enterprise modes", "contract_ready"),
    ]},
]


def build_enterprise_readiness_catalog() -> dict[str, Any]:
    controls = [control for category in ENTERPRISE_READINESS_CATALOG for control in category["controls"]]
    implemented = len([control for control in controls if control["status"] == "implemented"])
    contract_ready = len([control for control in controls if control["status"] == "contract_ready"])
    external = len([control for control in controls if control["status"] == "external_setup_required"])
    return {
        "categories": ENTERPRISE_READINESS_CATALOG,
        "summary": {
            "categories": len(ENTERPRISE_READINESS_CATALOG),
            "controls": len(controls),
            "implemented": implemented,
            "contract_ready": contract_ready,
            "external_setup_required": external,
            "readiness_score": round(((implemented + contract_ready * 0.65) / len(controls)) * 100),
            "final_bar": [
                "secure by default",
                "tenant-safe by default",
                "dry-run by default",
                "evidence-first by default",
                "every action audited",
                "every recommendation explainable",
                "every deployment reproducible",
            ],
        },
    }
