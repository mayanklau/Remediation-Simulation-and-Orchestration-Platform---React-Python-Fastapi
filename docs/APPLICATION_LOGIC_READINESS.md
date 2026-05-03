# Application Logic Readiness

The platform is app-logic ready when lifecycle transitions, validation gates, and invariants are enforced as product contracts, not only represented as UI screens.

Implemented logic contracts:

- Finding lifecycle: ingestion, dedupe, triage, actioning, validation, closure, false positive, exception.
- Remediation lifecycle: simulation, plan, approval, execution, validation, closure, blockers.
- Attack-path lifecycle: model, score, simulate, break, monitor, reopen.
- Connector lifecycle: secret reference, dry-run, certification, schedule, sync, stale-source handling.
- Evidence lifecycle: collect, complete, seal, export, legal hold.
- Tenant/RBAC lifecycle: SSO, role mapping, connector enablement, pilot readiness, production readiness.
- Exception lifecycle: request, assess, compensating control, approve, activate, renew, expire, revoke.
- Campaign lifecycle: scope, prioritize, wave planning, in-progress execution, blockers, validation, closure metrics.
- Approval lifecycle: policy route, pending approval, escalation, approval, rejection, expiry, superseded plan.
- Policy lifecycle: draft, simulation, conflict check, approval, publish, enforce, drift, retire.
- Policy-conflict lifecycle: detect overlap, classify, prioritize, resolve, waive, reopen.
- Simulation lifecycle: input validation, baseline, model, score, explain, review, snapshot, stale handling.
- Execution lifecycle: dry-run, live request, precheck, run, success, failure, rollback.
- Validation/reopen lifecycle: validation check, pass, fail, reopen, suppress, monitor.
- Rollback lifecycle: plan, arm, trigger, execute, restore, fail, postmortem.
- Connector certification lifecycle: field mapping, normalization, asset matching, dedupe, quality score, certification.
- Source trust lifecycle: score freshness and quality, trust, degrade, stale, quarantine, restore.
- Agentic action lifecycle: context bind, policy check, plan, dry-run, human approval, tool execution, audit.
- Production operations lifecycle: config validation, migration, deployment, observability, incident, recovery, DR validation.
- Executive reporting lifecycle: data validation, narrative, decision attachment, approval, publish, archive.
- Customer pilot acceptance lifecycle: real scanner data, mapping, paths, simulations, evidence, security review, signoff.

Hard acceptance rule: live remediation must be blocked unless simulation, plan, approval, rollback, and evidence gates are present.

Current readiness contract: 21 enforced lifecycle models, 130+ guarded transitions, and route/API coverage for exposing the model to the frontend. The App Logic screen reads these contracts directly from the backend so a reviewer can inspect the actual state machines, required gates, blocked conditions, invariants, and transition-guard examples.
