#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8001/api}"

echo "Loading enterprise remediation demo data into ${API_BASE} ..."

node <<'NODE'
const API = process.env.API_BASE || "http://localhost:8001/api";

const findings = [
  {
    source: "tenable",
    source_id: "TENABLE-EDGE-RCE-001",
    title: "Internet exposed admin service with active exploitation",
    severity: "CRITICAL",
    category: "network_policy",
    scanner_severity: "Critical",
    exploit_available: true,
    active_exploitation: true,
    patch_available: false,
    metadata: { cvss: 9.8, epss: 0.94, kev: true, mitre: "T1190" },
    asset: { external_id: "prod-admin-01", name: "prod-admin-01", type: "VM", environment: "PRODUCTION", provider: "aws", region: "us-east-1", criticality: 5, data_sensitivity: 4, internet_exposure: true, owner: "infra-ops", compliance_scope: "SOC2" }
  },
  {
    source: "wiz",
    source_id: "WIZ-IAM-ADMIN-001",
    title: "Over-privileged production deployment role",
    severity: "CRITICAL",
    category: "iam_policy",
    control_id: "AWS-IAM-ADMIN-WILDCARD",
    scanner_severity: "Critical",
    exploit_available: true,
    patch_available: true,
    metadata: { account: "prod-security", toxic_combination: "ci_runner_token,iam_admin,production_account", epss: 0.86 },
    asset: { external_id: "iam-prod-deploy-role", name: "Prod Deploy IAM Role", type: "IAM_ROLE", environment: "PRODUCTION", provider: "aws", region: "global", criticality: 5, data_sensitivity: 4, internet_exposure: false, owner: "platform-engineering", compliance_scope: "SOC2" }
  },
  {
    source: "github-advanced-security",
    source_id: "GHAS-SECRET-991",
    title: "Production database credential exposed in build logs",
    severity: "CRITICAL",
    category: "secrets",
    scanner_severity: "Critical",
    exploit_available: true,
    active_exploitation: true,
    patch_available: true,
    metadata: { secret_type: "postgres_password", rotation_required: true, epss: 0.91 },
    asset: { external_id: "github-actions-prod-runner", name: "GitHub Actions Production Runner", type: "CI_CD", environment: "PRODUCTION", provider: "github", criticality: 5, data_sensitivity: 5, internet_exposure: true, owner: "devsecops", compliance_scope: "SOC2" }
  },
  {
    source: "prisma-cloud",
    source_id: "PCC-K8S-4420",
    title: "Privileged Kubernetes workload mounts host filesystem",
    severity: "HIGH",
    category: "kubernetes_policy",
    scanner_severity: "High",
    exploit_available: true,
    patch_available: true,
    metadata: { cluster: "eks-prod-payments", namespace: "payments", epss: 0.72 },
    asset: { external_id: "eks-prod-payments", name: "EKS Payments Cluster", type: "KUBERNETES_CLUSTER", environment: "PRODUCTION", provider: "aws", region: "us-east-1", criticality: 5, data_sensitivity: 5, internet_exposure: false, owner: "payments-platform", compliance_scope: "PCI" }
  }
];

const integrations = [
  { provider: "tenable-enterprise", name: "Tenable Enterprise VM", category: "scanner", auth_mode: "manual_secret_reference", endpoint: "https://tenable.example.internal", owner: "security-operations", scopes: "read:findings,read:assets", operation: "ingest_findings" },
  { provider: "wiz-cloud", name: "Wiz Cloud Security", category: "cloud", auth_mode: "manual_secret_reference", endpoint: "https://api.wiz.example.internal", owner: "cloud-security", scopes: "read:issues,read:assets,read:iam", operation: "ingest_cloud_findings" },
  { provider: "github-advanced-security", name: "GitHub Advanced Security", category: "code", auth_mode: "manual_secret_reference", endpoint: "https://api.github.com", owner: "devsecops", scopes: "repo,security_events,workflow", operation: "ingest_code_findings" }
];

async function post(path, body = {}) {
  const response = await fetch(`${API}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error(`${path} ${response.status}: ${await response.text()}`);
  return response.json();
}

async function get(path) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`${path} ${response.status}: ${await response.text()}`);
  return response.json();
}

console.log("1/5 Ingesting representative scanner and posture findings...");
console.log(await post("/ingest/json", { findings }));

console.log("2/5 Appending integrations...");
for (const integration of integrations) await post("/integrations", integration);

console.log("3/5 Running connector dry checks and governance modules...");
for (const integration of integrations) await post("/connectors/live", { provider: integration.provider, operation: integration.operation, dry_run: true, payload: { demo: true } });
await post("/virtual-patching", { action: "activate" });
await post("/agentic", { goal: "reduce production attack paths", prompt: "Plan governed path breakers for exploited production paths.", dry_run: true });
await post("/attack-paths", { action: "snapshot" });

console.log("4/5 Creating simulations, plans, and workflows...");
const actions = (await get("/remediation-actions")).actions || [];
for (const action of actions.slice(0, 4)) {
  await post(`/remediation-actions/${action._id}/simulate`, {});
  await post(`/remediation-actions/${action._id}/plan`, {});
  await post(`/remediation-actions/${action._id}/workflow`, {});
}

console.log("5/5 Verifying state...");
const dashboard = await get("/dashboard");
const attackPaths = await get("/attack-paths");
console.log(JSON.stringify({
  assets: dashboard.counts.assets,
  open_findings: dashboard.counts.open_findings,
  remediation_actions: dashboard.counts.remediation_actions,
  simulations: dashboard.counts.simulations,
  workflows: dashboard.counts.workflows,
  attack_paths: attackPaths.attack_paths?.summary?.total_paths || attackPaths.attack_paths?.paths?.length || 0
}, null, 2));
NODE
