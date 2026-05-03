# Application Logic Readiness

The platform is app-logic ready when lifecycle transitions, validation gates, and invariants are enforced as product contracts, not only represented as UI screens.

Implemented logic contracts:

- Finding lifecycle: ingestion, dedupe, triage, actioning, validation, closure, false positive, exception.
- Remediation lifecycle: simulation, plan, approval, execution, validation, closure, blockers.
- Attack-path lifecycle: model, score, simulate, break, monitor, reopen.
- Connector lifecycle: secret reference, dry-run, certification, schedule, sync, stale-source handling.
- Evidence lifecycle: collect, complete, seal, export, legal hold.
- Tenant/RBAC lifecycle: SSO, role mapping, connector enablement, pilot readiness, production readiness.

Hard acceptance rule: live remediation must be blocked unless simulation, plan, approval, rollback, and evidence gates are present.
