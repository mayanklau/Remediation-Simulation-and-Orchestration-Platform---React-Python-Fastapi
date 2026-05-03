# Subject Matter Maturity Pack

This pack explains how the platform proves enterprise-grade vulnerability analytics beyond severity sorting.

## Scanner Certification

Each scanner adapter should pass a certification track before customer use:

- Tenable VM/Nessus: plugin, CVE, VPR, asset UUID, port, protocol, exploit fields.
- Qualys VMDR: QID, CVE, threat, impact, solution, host identity, tracking method.
- Wiz: issue, toxic combination, cloud resource, account, attack path, data exposure.
- Prisma Cloud: policy, resource, cloud account, compliance standard, runtime scope.
- Snyk: package, version, fixed version, exploit maturity, project, repository.
- GitHub Advanced Security: code scanning alert, rule, secret type, repository, workflow.

Acceptance requires sample export, parser contract, normalized finding, asset match, and evidence trace.

## Attack-Path Risk Science

Every path should show MITRE stage, exploit preconditions, required privilege, reachability, evidence confidence, business impact, pre-remediation risk, post-remediation residual risk, path breaker, and validation method.

## Control Effectiveness

Supported controls include patch, WAF rule, IAM deny, segmentation, secret rotation, cloud policy, and Kubernetes policy. Each control must define objective, expected risk delta, operational friction, validation method, and rollback evidence.

## Validation And Exceptions

Every closure requires before state, applied control, validation result, residual risk, owner, timestamp, and correlation ID. Every exception requires expiry, compensating control, business justification, risk owner, and approval evidence.

## Pilot Acceptance

The pilot is accepted when the customer can load at least two real scanner exports, see five vulnerability chains, simulate five control types, generate evidence for closure and exception, and agree on measurable risk-reduction metrics.
