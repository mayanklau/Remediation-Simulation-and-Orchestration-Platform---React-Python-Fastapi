# Enterprise Maturity Additions

This release adds the engineering and product maturity layer requested for the React/FastAPI/MongoDB version of Remediation Twin.

## Development Maturity

- SSO/OIDC production contract, tenant-boundary dependency, RBAC permission helper, and route-level enforcement contracts.
- Repository/service structure for separating API routing from persistence logic and shared validation.
- Queue-worker contracts for ingestion, simulation, connector sync, evidence generation, and report snapshots.
- Runtime configuration validation for local, dev, staging, and production.
- Contract tests for production config, RBAC enforcement, and worker correlation.
- CI/CD gates for Python compile, pytest, frontend build, dependency audit, and container-scan readiness.
- Correlation IDs on protected APIs for audit and observability joins.
- Feature flags for autonomous remediation and model-based planning.

## Subject Maturity

- Attack-path graph algorithms for shortest exploitable path, bounded k-hop blast radius, centrality-style concentration, choke points, and crown-jewel exposure.
- Vulnerability chaining rules for network, IAM, cloud, Kubernetes, application, CI/CD, secrets, and data-store findings.
- Exploit precondition modeling for privilege, network access, user interaction, token scope, lateral movement, and control friction.
- Difficulty scoring with explainability and assumptions.
- Before/after risk simulation per control: patch, WAF/API rule, IAM deny, segmentation, container rebuild, and cloud policy.
- Path-breaker recommendation engine that identifies the edge/control that removes the most risk with the least change risk.
- Scanner normalization roadmap for Tenable, Qualys, Wiz, Prisma Cloud, Snyk, GitHub Advanced Security, AWS Security Hub, Defender, and CrowdStrike.
- Evidence packs with before state, simulation, approval, execution log, validation, and residual risk.
- Executive views for business services at risk, weekly risk reduced, blocked remediations, and attack paths closed.
