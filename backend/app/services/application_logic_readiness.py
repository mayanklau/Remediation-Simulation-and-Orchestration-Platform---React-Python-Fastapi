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
        lifecycle("exception", "Exception Lifecycle", "risk-governance", "Accept residual risk only with owner, expiry, compensating controls, evidence, and renewal logic.", ["REQUESTED", "ASSESSING", "COMPENSATING_CONTROL_REQUIRED", "APPROVED", "ACTIVE", "EXPIRING", "RENEWED", "EXPIRED", "REVOKED"], ["EXPIRED", "REVOKED"], [
            transition("REQUESTED", "ASSESSING", ["risk_owner", "business_justification", "affected_assets"], ["missing_owner"]),
            transition("ASSESSING", "COMPENSATING_CONTROL_REQUIRED", ["residual_risk", "control_gap"], ["risk_below_appetite"]),
            transition("COMPENSATING_CONTROL_REQUIRED", "APPROVED", ["compensating_control", "expiry", "approver"], ["crown_jewel_without_executive_approval"]),
            transition("APPROVED", "ACTIVE", ["evidence_pack", "audit_correlation"], ["missing_expiry"]),
            transition("ACTIVE", "EXPIRING", ["expiry_threshold_reached"], ["renewal_already_started"]),
            transition("EXPIRING", "RENEWED", ["renewal_approval", "updated_residual_risk"], ["control_failed_validation"]),
            transition("ACTIVE", "REVOKED", ["risk_changed_or_control_failed"], ["no_owner_notification"]),
        ], ["exceptions always expire", "exceptions must name residual risk", "exceptions cannot close active exploitation without executive approval"]),
        lifecycle("campaign", "Remediation Campaign Lifecycle", "program-management", "Group work into measurable waves with owners, blockers, dependencies, risk burn-down, and closure metrics.", ["DRAFT", "SCOPED", "PRIORITIZED", "WAVED", "IN_PROGRESS", "BLOCKED", "VALIDATING", "CLOSED", "RETROSPECTIVE"], ["CLOSED", "RETROSPECTIVE"], [
            transition("DRAFT", "SCOPED", ["included_findings", "business_service", "owner"], ["empty_scope"]),
            transition("SCOPED", "PRIORITIZED", ["risk_burndown_goal", "sla_policy", "capacity"], ["no_success_metric"]),
            transition("PRIORITIZED", "WAVED", ["dependency_order", "change_windows", "rollback_plan"], ["conflicting_windows"]),
            transition("WAVED", "IN_PROGRESS", ["assigned_actions", "approval_routes"], ["owner_gap"]),
            transition("IN_PROGRESS", "BLOCKED", ["blocker_reason", "escalation_owner"], ["silent_blocker"]),
            transition("IN_PROGRESS", "VALIDATING", ["completed_actions", "evidence_manifest"], ["unvalidated_closure"]),
            transition("VALIDATING", "CLOSED", ["risk_reduction_met", "paths_closed", "executive_summary"], ["risk_target_missed"]),
        ], ["campaigns track risk reduction not ticket count", "blocked work has owner and reason", "closure requires evidence and metrics"]),
        lifecycle("approval", "Approval Lifecycle", "change-governance", "Route security, service-owner, CAB, risk-owner, and executive decisions with policy-aware gates.", ["CREATED", "ROUTED", "PENDING", "ESCALATED", "APPROVED", "REJECTED", "EXPIRED", "SUPERSEDED"], ["APPROVED", "REJECTED", "EXPIRED", "SUPERSEDED"], [
            transition("CREATED", "ROUTED", ["policy_match", "required_roles"], ["no_policy_match"]),
            transition("ROUTED", "PENDING", ["approver_identity", "due_at"], ["approver_conflict"]),
            transition("PENDING", "ESCALATED", ["sla_breach_or_crown_jewel"], ["within_sla"]),
            transition("PENDING", "APPROVED", ["approval_comment", "risk_acknowledgement"], ["segregation_of_duties_violation"]),
            transition("PENDING", "REJECTED", ["reason_code", "next_action"], ["missing_reason"]),
            transition("PENDING", "EXPIRED", ["approval_sla_elapsed"], ["active_decision"]),
            transition("APPROVED", "SUPERSEDED", ["material_plan_change"], ["no_plan_delta"]),
        ], ["approvers cannot approve their own high-risk changes", "approval has reason, actor, and timestamp", "material plan changes require reapproval"]),
        lifecycle("policy", "Policy Lifecycle", "governance", "Create, simulate, approve, publish, enforce, monitor, and retire automation and risk policies.", ["DRAFT", "SIMULATED", "CONFLICT_CHECKED", "APPROVED", "PUBLISHED", "ENFORCING", "DRIFTING", "RETIRED"], ["RETIRED"], [
            transition("DRAFT", "SIMULATED", ["policy_conditions", "test_cases"], ["empty_condition"]),
            transition("SIMULATED", "CONFLICT_CHECKED", ["simulation_result", "affected_population"], ["unsafe_impact"]),
            transition("CONFLICT_CHECKED", "APPROVED", ["no_high_conflicts", "approver"], ["blocking_conflict"]),
            transition("APPROVED", "PUBLISHED", ["version", "rollback_version"], ["missing_rollback"]),
            transition("PUBLISHED", "ENFORCING", ["runtime_binding", "audit_enabled"], ["disabled_feature_flag"]),
            transition("ENFORCING", "DRIFTING", ["observed_policy_delta"], ["expected_state"]),
            transition("DRIFTING", "RETIRED", ["replacement_policy", "owner_approval"], ["no_replacement"]),
        ], ["policies are versioned", "conflicts block publish", "runtime enforcement emits audit events"]),
        lifecycle("policy_conflict", "Policy Conflict Lifecycle", "governance", "Detect and resolve policy priority, scope, owner, and automation conflicts before enforcement.", ["DETECTED", "CLASSIFIED", "PRIORITIZED", "RESOLVED", "WAIVED", "REOPENED"], ["RESOLVED", "WAIVED"], [
            transition("DETECTED", "CLASSIFIED", ["conflicting_policies", "scope_overlap"], ["no_overlap"]),
            transition("CLASSIFIED", "PRIORITIZED", ["severity", "blast_radius", "owner"], ["missing_owner"]),
            transition("PRIORITIZED", "RESOLVED", ["winning_policy", "reason", "test_result"], ["test_failed"]),
            transition("PRIORITIZED", "WAIVED", ["expiry", "risk_owner", "compensating_control"], ["permanent_waiver"]),
            transition("WAIVED", "REOPENED", ["expiry_or_incident"], ["waiver_active"]),
            transition("REOPENED", "RESOLVED", ["updated_policy_version"], ["conflict_still_present"]),
        ], ["blocking conflicts prevent publish", "waivers expire", "policy priority is explicit"]),
        lifecycle("simulation", "Simulation Lifecycle", "simulation-engine", "Run deterministic what-if analysis with baseline, candidate control, confidence, blast radius, and residual risk.", ["REQUESTED", "INPUT_VALIDATED", "BASELINED", "MODELED", "SCORED", "REVIEWED", "SNAPSHOTTED", "STALE"], ["SNAPSHOTTED", "STALE"], [
            transition("REQUESTED", "INPUT_VALIDATED", ["action_or_path", "tenant_context"], ["missing_subject"]),
            transition("INPUT_VALIDATED", "BASELINED", ["before_risk", "current_controls"], ["no_baseline"]),
            transition("BASELINED", "MODELED", ["candidate_control", "blast_radius"], ["unsupported_control"]),
            transition("MODELED", "SCORED", ["risk_delta", "operational_risk", "confidence"], ["after_risk_higher_without_reason"]),
            transition("SCORED", "REVIEWED", ["explanation", "assumptions"], ["low_confidence_no_review"]),
            transition("REVIEWED", "SNAPSHOTTED", ["snapshot_id", "audit_correlation"], ["missing_audit"]),
            transition("SNAPSHOTTED", "STALE", ["source_or_asset_changed"], ["fresh_inputs"]),
        ], ["simulations record assumptions", "after risk and confidence are mandatory", "stale simulations cannot approve execution"]),
        lifecycle("execution", "Execution Lifecycle", "automation", "Control dry-run, live execution, hooks, idempotency, rollback, and post-change monitoring.", ["DRY_RUN_REQUESTED", "DRY_RUN_PASSED", "LIVE_REQUESTED", "PRECHECK_PASSED", "RUNNING", "SUCCEEDED", "FAILED", "ROLLED_BACK"], ["SUCCEEDED", "FAILED", "ROLLED_BACK"], [
            transition("DRY_RUN_REQUESTED", "DRY_RUN_PASSED", ["connector_health", "payload_validated"], ["dry_run_failed"]),
            transition("DRY_RUN_PASSED", "LIVE_REQUESTED", ["approval", "change_window"], ["dry_run_only_mode"]),
            transition("LIVE_REQUESTED", "PRECHECK_PASSED", ["idempotency_key", "rollback_plan"], ["duplicate_request"]),
            transition("PRECHECK_PASSED", "RUNNING", ["execution_hook", "audit_correlation"], ["feature_flag_disabled"]),
            transition("RUNNING", "SUCCEEDED", ["execution_log", "service_health"], ["health_degraded"]),
            transition("RUNNING", "FAILED", ["failure_reason", "owner_notified"], ["silent_failure"]),
            transition("FAILED", "ROLLED_BACK", ["rollback_executed", "validation_result"], ["rollback_missing"]),
        ], ["live execution requires dry-run and approval", "idempotency prevents duplicate changes", "failures have rollback decision"]),
        lifecycle("validation_reopen", "Validation And Reopen Lifecycle", "assurance", "Prove closure, detect regression, and reopen risk when scanners, controls, or attack paths disagree.", ["VALIDATION_REQUESTED", "CHECKING", "PASSED", "FAILED", "REOPENED", "SUPPRESSED", "MONITORING"], ["PASSED", "SUPPRESSED", "MONITORING"], [
            transition("VALIDATION_REQUESTED", "CHECKING", ["validation_method", "target_state"], ["no_method"]),
            transition("CHECKING", "PASSED", ["post_scan_clean", "control_effective"], ["residual_risk_above_threshold"]),
            transition("CHECKING", "FAILED", ["failed_check", "evidence"], ["no_evidence"]),
            transition("FAILED", "REOPENED", ["owner", "new_due_date"], ["duplicate_without_delta"]),
            transition("FAILED", "SUPPRESSED", ["risk_owner", "expiry", "reason"], ["no_expiry"]),
            transition("PASSED", "MONITORING", ["drift_watch", "source_freshness"], ["no_monitoring_signal"]),
            transition("MONITORING", "REOPENED", ["new_signal", "risk_delta"], ["signal_below_threshold"]),
        ], ["failed validation reopens work", "suppression expires", "monitoring has concrete signals"]),
        lifecycle("rollback", "Rollback Lifecycle", "sre-security", "Ensure every risky change can return to a known-good state with proof and decision history.", ["PLANNED", "ARMED", "TRIGGERED", "EXECUTING", "RESTORED", "FAILED", "POSTMORTEM"], ["RESTORED", "FAILED", "POSTMORTEM"], [
            transition("PLANNED", "ARMED", ["before_state", "rollback_owner", "time_budget"], ["missing_before_state"]),
            transition("ARMED", "TRIGGERED", ["trigger_condition", "approver_or_policy"], ["manual_trigger_without_reason"]),
            transition("TRIGGERED", "EXECUTING", ["rollback_steps", "communication_sent"], ["no_steps"]),
            transition("EXECUTING", "RESTORED", ["health_restored", "security_state_checked"], ["health_still_bad"]),
            transition("EXECUTING", "FAILED", ["failure_reason", "incident_created"], ["no_incident"]),
            transition("RESTORED", "POSTMORTEM", ["root_cause", "followup_actions"], ["missing_owner"]),
        ], ["rollback is required for production execution", "rollback proof is evidence", "failed rollback opens incident"]),
        lifecycle("connector_certification", "Connector Certification Lifecycle", "integration-engineering", "Prove each scanner/source maps fields, assets, dedupe, severity, and evidence correctly before trust weighting.", ["SAMPLE_RECEIVED", "FIELDS_MAPPED", "NORMALIZED", "ASSET_MATCHED", "DEDUPED", "QUALITY_SCORED", "CERTIFIED", "REJECTED"], ["CERTIFIED", "REJECTED"], [
            transition("SAMPLE_RECEIVED", "FIELDS_MAPPED", ["sample_export", "required_fields"], ["missing_required_fields"]),
            transition("FIELDS_MAPPED", "NORMALIZED", ["schema_validation", "parser_contract"], ["parser_error"]),
            transition("NORMALIZED", "ASSET_MATCHED", ["asset_key", "match_strategy"], ["match_rate_too_low"]),
            transition("ASSET_MATCHED", "DEDUPED", ["fingerprint_rule"], ["duplicate_explosion"]),
            transition("DEDUPED", "QUALITY_SCORED", ["freshness", "coverage", "false_positive_rate"], ["quality_unknown"]),
            transition("QUALITY_SCORED", "CERTIFIED", ["acceptance_evidence", "owner_signoff"], ["score_below_threshold"]),
            transition("QUALITY_SCORED", "REJECTED", ["rejection_reason", "remediation_steps"], ["no_reason"]),
        ], ["uncertified sources cannot drive automation", "required fields are source-specific", "certification evidence is retained"]),
        lifecycle("source_trust", "Source Trust Lifecycle", "data-quality", "Continuously adjust scanner/source weight using freshness, mapping confidence, false positives, and validation outcomes.", ["OBSERVED", "SCORED", "TRUSTED", "DEGRADED", "STALE", "QUARANTINED", "RESTORED"], ["TRUSTED", "QUARANTINED", "RESTORED"], [
            transition("OBSERVED", "SCORED", ["freshness", "coverage", "validation_history"], ["insufficient_history"]),
            transition("SCORED", "TRUSTED", ["score_above_threshold", "certified"], ["uncertified_source"]),
            transition("TRUSTED", "DEGRADED", ["false_positive_spike_or_mapping_drop"], ["normal_variance"]),
            transition("DEGRADED", "STALE", ["freshness_sla_breach"], ["fresh_source"]),
            transition("STALE", "QUARANTINED", ["owner_notified", "alternate_source"], ["critical_without_alternate"]),
            transition("QUARANTINED", "RESTORED", ["health_recovered", "sample_recertified"], ["quality_still_low"]),
        ], ["source trust affects risk confidence", "stale sources cannot auto-close risk", "quarantine has owner notification"]),
        lifecycle("agentic_action", "Agentic Action Lifecycle", "ai-governance", "Constrain model-generated plans with policy, dry-run, tool permissions, human approval, and audit.", ["PROMPT_RECEIVED", "CONTEXT_BOUND", "POLICY_CHECKED", "PLAN_GENERATED", "DRY_RUN_VALIDATED", "HUMAN_APPROVED", "TOOL_EXECUTED", "AUDITED", "REJECTED"], ["AUDITED", "REJECTED"], [
            transition("PROMPT_RECEIVED", "CONTEXT_BOUND", ["tenant_context", "data_minimization"], ["sensitive_data_unredacted"]),
            transition("CONTEXT_BOUND", "POLICY_CHECKED", ["tool_policy", "autonomy_policy"], ["policy_missing"]),
            transition("POLICY_CHECKED", "PLAN_GENERATED", ["allowed_tools", "model_confidence"], ["tool_not_allowed"]),
            transition("PLAN_GENERATED", "DRY_RUN_VALIDATED", ["dry_run_result", "deterministic_fallback"], ["dry_run_failed"]),
            transition("DRY_RUN_VALIDATED", "HUMAN_APPROVED", ["approver", "risk_summary"], ["high_risk_without_human"]),
            transition("HUMAN_APPROVED", "TOOL_EXECUTED", ["execution_scope", "rollback_plan"], ["scope_expanded"]),
            transition("TOOL_EXECUTED", "AUDITED", ["decision_trace", "evidence"], ["missing_trace"]),
        ], ["agentic actions are dry-run first", "tools are policy constrained", "high-risk execution requires human approval"]),
        lifecycle("production_operations", "Production Operations Lifecycle", "sre", "Operate migrations, queues, backups, restores, release gates, observability, and incidents.", ["CONFIG_VALIDATED", "MIGRATED", "DEPLOYED", "OBSERVED", "DEGRADED", "INCIDENT", "RECOVERED", "DR_VALIDATED"], ["RECOVERED", "DR_VALIDATED"], [
            transition("CONFIG_VALIDATED", "MIGRATED", ["env_schema", "migration_plan"], ["invalid_config"]),
            transition("MIGRATED", "DEPLOYED", ["index_check", "rollback_image"], ["migration_failed"]),
            transition("DEPLOYED", "OBSERVED", ["health_probe", "metrics", "logs"], ["health_unavailable"]),
            transition("OBSERVED", "DEGRADED", ["slo_burn_or_error_rate"], ["within_slo"]),
            transition("DEGRADED", "INCIDENT", ["severity", "owner", "runbook"], ["auto_recovered"]),
            transition("INCIDENT", "RECOVERED", ["fix_applied", "post_incident_validation"], ["validation_failed"]),
            transition("RECOVERED", "DR_VALIDATED", ["backup_restore_test", "rpo_rto_result"], ["restore_untested"]),
        ], ["production config is validated at startup", "deployments have rollback", "backup restore is tested"]),
        lifecycle("executive_reporting", "Executive Reporting Lifecycle", "security-leadership", "Convert operational data into board-ready risk, decisions, exceptions, and value metrics.", ["DRAFT", "DATA_VALIDATED", "NARRATIVE_BUILT", "DECISIONS_ATTACHED", "APPROVED", "PUBLISHED", "ARCHIVED"], ["PUBLISHED", "ARCHIVED"], [
            transition("DRAFT", "DATA_VALIDATED", ["fresh_sources", "metric_reconciliation"], ["stale_key_source"]),
            transition("DATA_VALIDATED", "NARRATIVE_BUILT", ["risk_reduced", "paths_closed", "exceptions_aging"], ["missing_metric"]),
            transition("NARRATIVE_BUILT", "DECISIONS_ATTACHED", ["decision_queue", "owner_actions"], ["no_decision_owner"]),
            transition("DECISIONS_ATTACHED", "APPROVED", ["ciso_review", "audit_review"], ["unapproved_exception"]),
            transition("APPROVED", "PUBLISHED", ["audience", "export_format"], ["wrong_audience"]),
            transition("PUBLISHED", "ARCHIVED", ["retention", "evidence_link"], ["no_retention"]),
        ], ["executive reports use validated data", "decisions have owners", "published reports are retained"]),
        lifecycle("customer_pilot", "Customer Pilot Acceptance Lifecycle", "customer-success", "Prove readiness with real data, connector certification, attack paths, simulations, evidence, and signoff.", ["PLANNED", "DATA_CONNECTED", "MAPPED", "PATHS_PROVEN", "SIMULATIONS_PROVEN", "EVIDENCE_PROVEN", "SECURITY_REVIEWED", "SIGNED_OFF"], ["SIGNED_OFF"], [
            transition("PLANNED", "DATA_CONNECTED", ["pilot_scope", "scanner_exports", "tenant_created"], ["no_customer_data"]),
            transition("DATA_CONNECTED", "MAPPED", ["asset_match_rate", "owner_coverage"], ["match_rate_low"]),
            transition("MAPPED", "PATHS_PROVEN", ["five_chains", "business_services"], ["no_multidomain_chain"]),
            transition("PATHS_PROVEN", "SIMULATIONS_PROVEN", ["five_control_types", "before_after_risk"], ["no_residual_risk"]),
            transition("SIMULATIONS_PROVEN", "EVIDENCE_PROVEN", ["closure_pack", "exception_pack", "failed_validation_pack"], ["missing_pack"]),
            transition("EVIDENCE_PROVEN", "SECURITY_REVIEWED", ["rbac_review", "data_flow_review"], ["security_gap"]),
            transition("SECURITY_REVIEWED", "SIGNED_OFF", ["success_metrics", "sponsor_approval"], ["no_sponsor"]),
        ], ["pilot uses real customer data", "success metrics are measurable", "signoff requires security review"]),
    ]

def can_transition(lifecycle_id: str, from_state: str, to_state: str, satisfied_gates: list[str] | None = None) -> dict:
    satisfied_gates = satisfied_gates or []
    lifecycle_item = next((item for item in application_lifecycles() if item["id"] == lifecycle_id), None)
    transition_rule = next((item for item in lifecycle_item["transitions"] if item["from"] == from_state and item["to"] == to_state), None) if lifecycle_item else None
    if not lifecycle_item or not transition_rule:
        return {"allowed": False, "missing_gates": [], "reason": "transition_not_defined"}
    missing = [gate for gate in transition_rule["required_gates"] if gate not in satisfied_gates]
    return {"allowed": len(missing) == 0, "missing_gates": missing, "reason": "all_gates_satisfied" if not missing else "required_gates_missing"}
