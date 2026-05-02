def lane(id: str, name: str, purpose: str, trigger: str, idempotency_key: str, metrics: list[str], status: str) -> dict:
    return {
        "id": id,
        "name": name,
        "purpose": purpose,
        "trigger": trigger,
        "retry": {"attempts": 3, "backoff": "exponential", "dead_letter": f"{id}_dead_letter"},
        "idempotency_key": idempotency_key,
        "metrics": metrics,
        "status": status,
    }


def quality(id: str, name: str, rule: str, fail_action: str, owner: str, status: str) -> dict:
    return {"id": id, "name": name, "rule": rule, "fail_action": fail_action, "owner": owner, "status": status}


def validation(id: str, name: str, evidence: str, automation: str, status: str) -> dict:
    return {"id": id, "name": name, "evidence": evidence, "automation": automation, "status": status}


def signal(id: str, name: str, metric: str, alert: str, runbook: str, status: str) -> dict:
    return {"id": id, "name": name, "metric": metric, "alert": alert, "runbook": runbook, "status": status}


def build_production_effectiveness_model() -> dict:
    scheduler_lanes = [
        lane("ingestion", "Ingestion Scheduler", "Pull and normalize scanner, CMDB, cloud, code, IAM, and custom feeds.", "cron/webhook/manual", "tenant:source:window", ["queue_depth", "records_normalized", "dedupe_ratio"], "implemented"),
        lane("simulation", "Simulation Worker", "Run blast-radius and before/after risk simulation before remediation.", "event/manual", "tenant:action:simulation_version", ["simulation_latency", "risk_delta", "confidence"], "implemented"),
        lane("connector_sync", "Connector Sync Worker", "Execute dry-run connector health checks and approved sync operations.", "cron/manual", "tenant:provider:operation", ["connector_success_rate", "failed_connector_runs"], "implemented"),
        lane("evidence_generation", "Evidence Pack Worker", "Collect before state, approval, execution, validation, and residual-risk evidence.", "event/manual", "tenant:workflow:evidence_version", ["sealed_packs", "unsealed_evidence"], "implemented"),
        lane("report_snapshot", "Report Snapshot Worker", "Freeze executive and audit metrics for weekly governance reporting.", "cron/manual", "tenant:report:period", ["snapshot_count", "report_freshness_hours"], "implemented"),
        lane("post_remediation_validation", "Post-Remediation Validation", "Re-check scanner state, reachability, and compensating controls after change completion.", "event/schedule", "tenant:action:validation_window", ["validation_pass_rate", "residual_risk_delta"], "ready_to_wire"),
        lane("data_quality_scan", "Data Quality Scan", "Score source freshness, ownership coverage, duplicate findings, and stale assets.", "cron/manual", "tenant:data_quality:day", ["quality_score", "stale_source_count", "unowned_assets"], "ready_to_wire"),
        lane("connector_health_scheduler", "Connector Health Scheduler", "Continuously test credentials, scopes, latency, and last-success windows.", "cron", "tenant:connector:health_day", ["connector_health_score", "secret_rotation_due"], "ready_to_wire"),
    ]

    data_quality_controls = [
        quality("source_freshness", "Source Freshness", "Each production connector must report within its configured SLA window.", "mark source stale and exclude from auto-approval", "integrations", "ready_to_wire"),
        quality("required_fields", "Required Field Completeness", "Findings need asset, severity, source, category, title, and remediation signal.", "quarantine malformed rows", "data-platform", "implemented"),
        quality("owner_coverage", "Owner Coverage", "Production assets and actions must resolve an application or service owner.", "block execution workflow", "service-owners", "ready_to_wire"),
        quality("asset_mapping", "Asset Mapping Confidence", "Scanner assets must map to canonical inventory with confidence above threshold.", "route to analyst review", "security-operations", "implemented"),
        quality("duplicate_fingerprint", "Duplicate Fingerprint Guard", "Fingerprint collisions must be merged or reviewed before risk scoring.", "hold duplicate cluster", "data-platform", "implemented"),
        quality("exploit_signal", "Exploit Signal Quality", "Exploitability, active exploitation, KEV, and EPSS-like signals are scored separately.", "lower confidence and require human approval", "threat-intel", "ready_to_wire"),
        quality("control_coverage", "Control Coverage", "Before/after simulation must name the exact control and validation method.", "block customer-facing residual-risk statement", "remediation", "implemented"),
        quality("evidence_completeness", "Evidence Completeness", "Evidence packs need before state, approval, execution, validation, and residual risk.", "prevent evidence seal", "audit", "implemented"),
    ]

    validation_loop = [
        validation("before_state", "Capture Before State", "scanner finding, asset posture, attack path, and current risk", "connector read or imported snapshot", "implemented"),
        validation("approval_gate", "Approve Change", "policy decision, approver, comments, and change window", "workflow approval", "implemented"),
        validation("execution_proof", "Record Execution Proof", "ticket, commit, deployment, policy update, or compensating-control run", "connector dry-run/live handoff", "ready_to_wire"),
        validation("after_scan", "Re-Validate After State", "post-change scanner result and reachability check", "validation worker lane", "ready_to_wire"),
        validation("residual_risk", "Calculate Residual Risk", "before risk, after risk, path delta, assumptions, and confidence", "simulation engine", "implemented"),
        validation("evidence_seal", "Seal Evidence Pack", "hash, retention, tenant, workflow, and audit correlation", "evidence worker", "implemented"),
    ]

    observability_signals = [
        signal("queue_depth", "Queue Depth", "remediation.queue.depth", "depth over threshold for lane SLA", "scale worker or pause ingestion", "ready_to_wire"),
        signal("dead_letters", "Dead Letters", "remediation.queue.dead_letters", "any critical job dead-lettered", "inspect payload and replay safely", "ready_to_wire"),
        signal("connector_failures", "Connector Failures", "remediation.connector.failures", "provider failure rate above threshold", "rotate secret or reduce schedule", "implemented"),
        signal("validation_failures", "Validation Failures", "remediation.validation.failures", "post-remediation validation failed", "reopen action and recalculate risk", "ready_to_wire"),
        signal("stale_sources", "Stale Sources", "remediation.data.stale_sources", "source outside freshness SLA", "mark source stale and notify owner", "ready_to_wire"),
        signal("unsealed_evidence", "Unsealed Evidence", "remediation.evidence.unsealed", "evidence pack remains unsealed past SLA", "rerun evidence worker", "implemented"),
        signal("api_latency", "API P95 Latency", "http.server.duration.p95", "p95 exceeds production budget", "inspect traces and scale API", "external_required"),
        signal("tenant_denials", "Tenant Boundary Denials", "remediation.authz.denials", "unexpected tenant/RBAC denial burst", "review identity mapping", "implemented"),
    ]

    all_items = scheduler_lanes + data_quality_controls + validation_loop + observability_signals
    implemented = len([item for item in all_items if item["status"] == "implemented"])
    ready_to_wire = len([item for item in all_items if item["status"] == "ready_to_wire"])
    external_required = len([item for item in all_items if item["status"] == "external_required"])

    return {
        "summary": {
            "scheduler_lanes": len(scheduler_lanes),
            "data_quality_controls": len(data_quality_controls),
            "validation_steps": len(validation_loop),
            "observability_signals": len(observability_signals),
            "implemented": implemented,
            "ready_to_wire": ready_to_wire,
            "external_required": external_required,
            "effectiveness_score": round((implemented / len(all_items)) * 100),
            "production_posture": "repo_ready_customer_wiring_required",
        },
        "scheduler_lanes": scheduler_lanes,
        "data_quality_controls": data_quality_controls,
        "validation_loop": validation_loop,
        "observability_signals": observability_signals,
        "operating_rules": [
            "Never auto-approve remediation from stale scanner data.",
            "Every remediation must preserve a before/after residual-risk statement.",
            "Validation failure reopens the action and blocks evidence sealing.",
            "Dead-letter jobs are replayed only with the original correlation ID and idempotency key.",
            "Customer-specific connectors, secrets, SSO, telemetry, and alert routes are external go-live values.",
        ],
    }
