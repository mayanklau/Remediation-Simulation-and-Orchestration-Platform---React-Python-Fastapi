import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, Bot, Boxes, FileCheck, GitPullRequestArrow, LayoutDashboard, Network, ScrollText, ShieldAlert, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { AttackGraphViews } from "./AttackGraphViews";
import "./styles.css";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
type Route = "dashboard" | "findings" | "assets" | "attackPaths" | "remediation" | "virtual" | "agentic" | "policies" | "reports" | "audit" | "ops";
const nav: Array<[Route, string, React.ComponentType<{ size?: number }>]> = [
  ["dashboard", "Dashboard", LayoutDashboard],
  ["findings", "Findings", ShieldAlert],
  ["assets", "Assets", Boxes],
  ["attackPaths", "Attack Paths", Network],
  ["remediation", "Remediation", GitPullRequestArrow],
  ["virtual", "Virtual Patch", ShieldCheck],
  ["agentic", "Agentic", Bot],
  ["policies", "Policies", SlidersHorizontal],
  ["reports", "Reports", FileCheck],
  ["audit", "Audit", ScrollText],
  ["ops", "Operations", Activity]
];

async function api(path: string, options?: RequestInit) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: { "content-type": "application/json", ...(options?.headers || {}) }
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

function useApi(path: string, refresh = 0) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    let active = true;
    api(path).then((result) => active && setData(result)).catch(console.error);
    return () => { active = false; };
  }, [path, refresh]);
  return data;
}

function Header({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: React.ReactNode }) {
  return <header className="header"><div><p>{eyebrow}</p><h1>{title}</h1><span>{description}</span></div><div className="actions">{children}</div></header>;
}
function Metric({ label, value }: { label: string; value: React.ReactNode }) { return <div className="panel metric"><span>{label}</span><strong>{value}</strong></div>; }
function Json({ value }: { value: unknown }) { return <pre>{JSON.stringify(value, null, 2)}</pre>; }
function Table({ title, rows, columns }: { title?: string; rows: any[]; columns: string[] }) {
  return <section className="panel">{title && <h2>{title}</h2>}<table><thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead><tbody>{(rows || []).length === 0 && <tr><td colSpan={columns.length}>No records yet.</td></tr>}{(rows || []).map((row, index) => <tr key={row._id || row.id || index}>{columns.map((column) => <td key={column}>{String(row[column] ?? "")}</td>)}</tr>)}</tbody></table></section>;
}

type Props = { refresh: number; bump: () => void };

function Dashboard({ refresh, bump }: Props) {
  const data = useApi("/api/dashboard", refresh);
  return <><Header eyebrow="Enterprise command center" title="Dashboard" description="Risk, remediation, simulation, approval, and evidence posture."><button onClick={async () => { await api("/api/mock-ingest", { method: "POST", body: "{}" }); bump(); }}>Load prototype data</button></Header><section className="grid cols-4"><Metric label="Open Findings" value={data?.counts?.open_findings ?? 0} /><Metric label="Assets" value={data?.counts?.assets ?? 0} /><Metric label="Actions" value={data?.counts?.remediation_actions ?? 0} /><Metric label="Simulation Coverage" value={`${data?.risk?.simulation_coverage ?? 0}%`} /></section><Table title="Top Findings" rows={data?.top_findings || []} columns={["title", "severity", "business_risk_score", "status"]} /></>;
}
function Findings({ refresh }: Props) { const data = useApi("/api/findings", refresh); return <><Header eyebrow="Normalized backlog" title="Findings" description="Canonical findings after ingestion, deduplication, risk scoring, and asset mapping." /><Table rows={data?.findings || []} columns={["title", "severity", "business_risk_score", "source", "status"]} /></>; }
function Assets({ refresh }: Props) { const data = useApi("/api/assets", refresh); return <><Header eyebrow="Asset inventory" title="Assets" description="Systems, owners, exposure, criticality, and sensitivity." /><Table rows={data?.assets || []} columns={["name", "type", "environment", "criticality", "data_sensitivity", "internet_exposure"]} /></>; }

function AttackPaths({ refresh, bump }: Props) {
  const model = useApi("/api/attack-paths", refresh)?.attack_paths;
  return <>
    <Header eyebrow="Vulnerability chaining" title="Attack Path Analytics" description="Scanner-normalized attack paths with graph analysis, difficulty, and before/after remediation risk."><button onClick={async () => { await api("/api/attack-paths", { method: "POST", body: JSON.stringify({ action: "snapshot" }) }); bump(); }}>Snapshot analytics</button></Header>
    <section className="grid cols-4"><Metric label="Attack Paths" value={model?.summary?.attack_paths ?? 0} /><Metric label="Critical Paths" value={model?.summary?.critical_paths ?? 0} /><Metric label="Before Risk" value={`${model?.summary?.average_before_risk ?? 0}%`} /><Metric label="After Risk" value={`${model?.summary?.average_after_risk ?? 0}%`} /></section>
    <AttackGraphViews paths={model?.paths || []} />
    <Table rows={model?.paths || []} columns={["name", "difficulty", "before_remediation_risk", "after_remediation_risk", "risk_delta", "priority"]} />
    <Json value={model?.construction_method || {}} />
  </>;
}

function Remediation({ refresh, bump }: Props) {
  const data = useApi("/api/remediation-actions", refresh); const first = data?.actions?.[0]?._id;
  return <><Header eyebrow="Action queue" title="Remediation" description="Simulate, plan, approve, and evidence remediation before execution."><button disabled={!first} onClick={async () => { await api(`/api/remediation-actions/${first}/simulate`, { method: "POST", body: "{}" }); bump(); }}>Simulate first</button><button disabled={!first} onClick={async () => { await api(`/api/remediation-actions/${first}/plan`, { method: "POST", body: "{}" }); bump(); }}>Plan first</button><button disabled={!first} onClick={async () => { await api(`/api/remediation-actions/${first}/workflow`, { method: "POST", body: "{}" }); bump(); }}>Approve first</button></Header><Table rows={data?.actions || []} columns={["title", "action_type", "status", "expected_risk_reduction"]} /></>;
}
function Virtual({ refresh, bump }: Props) { const data = useApi("/api/virtual-patching", refresh); return <><Header eyebrow="Compensating controls" title="Virtual Patching" description="Protect exposed paths before permanent remediation is safe."><button onClick={async () => { await api("/api/virtual-patching", { method: "POST", body: "{}" }); bump(); }}>Activate controls</button></Header><section className="grid cols-3"><Metric label="Candidates" value={data?.summary?.virtual_patch_candidates ?? 0} /><Metric label="Path Breakers" value={data?.summary?.path_breaker_candidates ?? 0} /><Metric label="Policies" value={data?.summary?.active_policies ?? 0} /></section><Table rows={data?.candidates || []} columns={["asset", "control", "score"]} /></>; }
function Agentic({ refresh, bump }: Props) { const data = useApi("/api/agentic", refresh)?.agentic; return <><Header eyebrow="Model-agnostic autonomy" title="Agentic Orchestrator" description="Plan with any LLM, SLM, gateway, or deterministic fallback while keeping execution governed."><button onClick={async () => { await api("/api/agentic", { method: "POST", body: JSON.stringify({ goal: "virtual_patch", prompt: "Plan safest next actions with virtual patching and path breakers.", dry_run: true }) }); bump(); }}>Run agent plan</button></Header><section className="grid cols-4"><Metric label="Readiness" value={`${data?.readiness_score ?? 0}%`} /><Metric label="Status" value={data?.status ?? "unknown"} /><Metric label="Tools" value={data?.tool_registry?.length ?? 0} /><Metric label="Runs" value={data?.recent_agent_runs?.length ?? 0} /></section><Table title="Model Providers" rows={data?.providers || []} columns={["provider", "model", "configured"]} /><Table title="Tool Registry" rows={data?.tool_registry || []} columns={["name", "mode", "risk"]} /></>; }
function Policies({ refresh }: Props) { const data = useApi("/api/policies", refresh); return <><Header eyebrow="Governance" title="Policies" description="Freeze windows, evidence gates, virtual patches, and execution guardrails." /><Table rows={data?.policies || []} columns={["name", "policy_type", "enabled", "created_at"]} /></>; }
function Reports({ refresh }: Props) { const data = useApi("/api/reports", refresh); return <><Header eyebrow="Evidence" title="Reports" description="Report snapshots, agent plans, and governance exports." /><Table rows={data?.reports || []} columns={["name", "type", "created_by", "created_at"]} /></>; }
function Audit({ refresh }: Props) { const data = useApi("/api/audit", refresh); return <><Header eyebrow="Audit trail" title="Audit" description="Tenant-scoped audit records." /><Table rows={data?.audit || []} columns={["actor", "action", "entity_type", "created_at"]} /></>; }
function Ops({ refresh, bump }: Props) { const data = useApi("/api/observability", refresh); return <><Header eyebrow="Production operations" title="Operations" description="Worker runs, connector dry-runs, and observability."><button onClick={async () => { await api("/api/workers/run", { method: "POST", body: JSON.stringify({ lane: "simulation", limit: 3 }) }); bump(); }}>Run worker</button></Header><Json value={data} /></>; }

const pages: Record<Route, React.ComponentType<Props>> = { dashboard: Dashboard, findings: Findings, assets: Assets, attackPaths: AttackPaths, remediation: Remediation, virtual: Virtual, agentic: Agentic, policies: Policies, reports: Reports, audit: Audit, ops: Ops };
function App() { const [route, setRoute] = useState<Route>("dashboard"); const [refresh, setRefresh] = useState(0); const Page = useMemo(() => pages[route], [route]); return <div className="shell"><aside className="sidebar"><div className="brand"><span>R</span><strong>Remediation Twin</strong></div><nav>{nav.map(([key, label, Icon]) => <button className={route === key ? "active" : ""} key={key} onClick={() => setRoute(key)}><Icon size={18} />{label}</button>)}</nav></aside><main><Page refresh={refresh} bump={() => setRefresh((value) => value + 1)} /></main></div>; }

createRoot(document.getElementById("root")!).render(<App />);
