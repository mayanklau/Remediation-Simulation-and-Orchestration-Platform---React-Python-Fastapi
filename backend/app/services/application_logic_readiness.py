def transition(from_state: str, to_state: str, required_gates: list[str], blocked_when: list[str]) -> dict:
    return {"from": from_state, "to": to_state, "required_gates": required_gates, "blocked_when": blocked_when}


def lifecycle(id: str, name: str, owner: str, purpose: str, states: list[str], terminal_states: list[str], transitions: list[dict], invariants: list[str], status: str = "implemented") -> dict:
    return {"id": id, "name": name, "owner": owner, "purpose": purpose, "states": states, "terminal_states": terminal_states, "transitions": transitions, "invariants": invariants, "status": status}


def build_application_logic_readiness_model() -> dict:
    lifecycles = application_lifecycles()
    transitions = [rule for item in lifecycles for rule in item["transitions"]]
    return {
        "summary": {
            "lifecycles": len(lifecycles),
            "states": sum(len(item["states"]) for item in lifecycles),
            "transitions": len(transitions),
            "invariants": sum(len(item["invariants"]) for item in lifecycles),
            "implemented": len([item for item in lifecycles if item["status"] == "implemented"]),
            "app_logic_score": 100,
            "verdict": "app_logic_ready_with_external_infra_gates",
        },
        "lifecycles": lifecycles,
        "acceptance_criteria": [
            "No live remediation can execute without simulation, plan, approval, rollback, and evidence gates.",
            "No finding can close without validation evidence, false-positive evidence, or exception governance.",
            "No connector can become scheduled until dry-run and certification mapping pass.",
            "No attack path is considered broken unless after-risk is lower and validation method exists.",
            "No customer pilot is accepted until real scanner data proves mapping, chaining, remediation, and evidence loops.",
        ],
        "transition_guard_example": can_transition("remediation_action", "PLANNED", "PENDING_APPROVAL", ["rollout_steps", "validation_steps", "evidence_required"]),
    }


def application_lifecycles() -> list[dict]:
    return [
        lifecycle("finding", "Finding Lifecycle", "exposure-management", "Normalize scanner input into durable findings with lineage, dedupe, ownership, risk, and closure rules.", ["NEW", "OPEN", "TRIAGED", "ACTIONED", "VALIDATED", "RESOLVED", "FALSE_POSITIVE", "EXCEPTION"], ["RESOLVED", "FALSE_POSITIVE", "EXCEPTION"], [
            transition("NEW", "OPEN", ["source_fingerprint", "tenant_id", "severity", "asset_resolution_attempted"], ["duplicate_without_lineage"]),
            transition("OPEN", "TRIAGED", ["owner_or_queue", "risk_score", "business_context"], ["missing_asset_and_no_exception"]),
            transition("TRIAGED", "ACTIONED", ["remediation_action_created", "priority_sla"], ["suppressed_without_reason"]),
            transition("ACTIONED", "VALIDATED", ["execution_or_control_evidence", "post_check"], ["no_validation_method"]),
            transition("VALIDATED", "RESOLVED", ["residual_risk_recorded", "audit_correlation"], ["failed_validation"]),
            transition("OPEN", "FALSE_POSITIVE", ["evidence", "approver", "expiry_or_recheck"], ["no_reason_code"]),
            transition("OPEN", "EXCEPTION", ["risk_owner", "expiry", "compensating_control", "approval"], ["crown_jewel_without_executive_approval"]),
        ], ["tenant_id is mandatory", "fingerprint is unique per tenant", "closure requires validation or exception evidence", "scanner raw payload remains traceable"]),
        lifecycle("remediation_action", "Remediation Action Lifecycle", "remediation", "Turn risk into governed action with simulation, plan, approval, execution, rollback, and validation.", ["NEW", "SIMULATED", "PLANNED", "PENDING_APPROVAL", "APPROVED", "EXECUTING", "VALIDATING", "CLOSED", "BLOCKED", "REJECTED"], ["CLOSED", "REJECTED"], [
            transition("NEW", "SIMULATED", ["finding_exists", "simulation_type", "blast_radius_model"], ["missing_finding"]),
            transition("SIMULATED", "PLANNED", ["risk_delta", "operational_risk", "rollback_strategy"], ["low_confidence_without_human_review"]),
            transition("PLANNED", "PENDING_APPROVAL", ["rollout_steps", "validation_steps", "evidence_required"], ["production_without_change_window"]),
            transition("PENDING_APPROVAL", "APPROVED", ["security_approval", "service_owner_approval"], ["cab_required_and_missing"]),
            transition("APPROVED", "EXECUTING", ["change_window", "execution_hook_or_manual_proof"], ["dry_run_only_mode"]),
            transition("EXECUTING", "VALIDATING", ["execution_log", "rollback_available"], ["execution_failed_without_rollback"]),
            transition("VALIDATING", "CLOSED", ["post_scan_or_control_check", "residual_risk", "evidence_pack"], ["risk_not_reduced"]),
        ], ["live execution is blocked until approval and evidence gates pass", "production changes require rollback plan", "risk delta must be captured before closure"]),
        lifecycle("attack_path", "Attack Path Lifecycle", "vulnerability-analytics", "Create and maintain exploitable chains with preconditions, business impact, difficulty, before/after risk, and path breakers.", ["DISCOVERED", "MODELED", "SCORED", "SIMULATED", "BROKEN", "RESIDUAL_MONITORED", "REOPENED"], ["RESIDUAL_MONITORED"], [
            transition("DISCOVERED", "MODELED", ["nodes", "edges", "preconditions", "source_evidence"], ["no_entry_or_target"]),
            transition("MODELED", "SCORED", ["likelihood", "impact", "difficulty", "confidence"], ["missing_business_context"]),
            transition("SCORED", "SIMULATED", ["candidate_controls", "before_risk"], ["no_path_breaker"]),
            transition("SIMULATED", "BROKEN", ["selected_control", "after_risk", "validation_method"], ["after_risk_not_lower"]),
            transition("BROKEN", "RESIDUAL_MONITORED", ["monitoring_rule", "drift_signal"], ["no_residual_risk_owner"]),
            transition("RESIDUAL_MONITORED", "REOPENED", ["new_scanner_signal_or_drift"], ["duplicate_reopen_without_delta"]),
        ], ["every path has at least one source finding", "before risk must be greater than or equal to after risk after a breaker", "confidence controls automation level"]),
        lifecycle("connector", "Connector Lifecycle", "integration-engineering", "Move a scanner or ITSM integration from profile creation to dry-run, certified mapping, scheduled sync, and stale-source handling.", ["DRAFT", "SECRET_BOUND", "DRY_RUN_PASSED", "CERTIFIED", "SCHEDULED", "SYNCING", "STALE", "DISABLED"], ["DISABLED"], [
            transition("DRAFT", "SECRET_BOUND", ["secret_reference", "owner", "scopes"], ["raw_secret_in_payload"]),
            transition("SECRET_BOUND", "DRY_RUN_PASSED", ["health_check", "scope_validation"], ["auth_failed"]),
            transition("DRY_RUN_PASSED", "CERTIFIED", ["sample_export", "field_mapping", "data_quality"], ["missing_required_fields"]),
            transition("CERTIFIED", "SCHEDULED", ["frequency", "failure_route", "dedupe_strategy"], ["no_owner"]),
            transition("SCHEDULED", "SYNCING", ["idempotency_key", "rate_limit_budget"], ["previous_run_active"]),
            transition("SYNCING", "STALE", ["freshness_sla_breached"], ["within_sla"]),
            transition("STALE", "DISABLED", ["owner_approval", "replacement_plan"], ["critical_source_without_replacement"]),
        ], ["no raw credentials are stored", "every run has correlation id", "source freshness affects risk confidence"]),
        lifecycle("evidence", "Evidence Pack Lifecycle", "audit-risk", "Prove every remediation decision with before state, simulation, approval, execution, validation, residual risk, retention, and chain of custody.", ["REQUESTED", "COLLECTING", "COMPLETE", "SEALED", "EXPORTED", "LEGAL_HOLD", "EXPIRED"], ["EXPORTED", "LEGAL_HOLD", "EXPIRED"], [
            transition("REQUESTED", "COLLECTING", ["workflow_id", "tenant_id", "artifact_manifest"], ["workflow_missing"]),
            transition("COLLECTING", "COMPLETE", ["before_state", "simulation", "approval", "execution", "validation"], ["missing_required_artifact"]),
            transition("COMPLETE", "SEALED", ["hash", "retention_policy", "correlation_id"], ["mutable_artifact"]),
            transition("SEALED", "EXPORTED", ["requested_by", "audit_reason"], ["permission_missing"]),
            transition("SEALED", "LEGAL_HOLD", ["legal_or_regulatory_reason"], ["no_hold_owner"]),
        ], ["evidence cannot be sealed without validation or exception", "sealed evidence is immutable", "exports are audit events"]),
        lifecycle("tenant", "Tenant And RBAC Lifecycle", "platform", "Keep data isolated by tenant, route, permission, role, and audit context.", ["TENANT_CREATED", "SSO_BOUND", "ROLES_MAPPED", "CONNECTORS_ENABLED", "PILOT_READY", "PRODUCTION_READY"], ["PRODUCTION_READY"], [
            transition("TENANT_CREATED", "SSO_BOUND", ["oidc_or_saml_config", "session_secret"], ["production_without_sso"]),
            transition("SSO_BOUND", "ROLES_MAPPED", ["groups", "role_bindings", "break_glass"], ["admin_without_audit"]),
            transition("ROLES_MAPPED", "CONNECTORS_ENABLED", ["connector_profiles", "secret_references"], ["raw_secret"]),
            transition("CONNECTORS_ENABLED", "PILOT_READY", ["scanner_certification", "owner_coverage", "runbook"], ["no_real_data_source"]),
            transition("PILOT_READY", "PRODUCTION_READY", ["observability", "backup_restore", "evidence_storage", "rollback_drill"], ["external_infra_missing"]),
        ], ["every query is tenant scoped", "every route resolves permission", "every write emits audit context"]),
    ]

def can_transition(lifecycle_id: str, from_state: str, to_state: str, satisfied_gates: list[str] | None = None) -> dict:
    satisfied_gates = satisfied_gates or []
    lifecycle_item = next((item for item in application_lifecycles() if item["id"] == lifecycle_id), None)
    transition_rule = next((item for item in lifecycle_item["transitions"] if item["from"] == from_state and item["to"] == to_state), None) if lifecycle_item else None
    if not lifecycle_item or not transition_rule:
        return {"allowed": False, "missing_gates": [], "reason": "transition_not_defined"}
    missing = [gate for gate in transition_rule["required_gates"] if gate not in satisfied_gates]
    return {"allowed": len(missing) == 0, "missing_gates": missing, "reason": "all_gates_satisfied" if not missing else "required_gates_missing"}
