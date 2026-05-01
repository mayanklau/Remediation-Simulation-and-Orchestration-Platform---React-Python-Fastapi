import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  Bot,
  Boxes,
  CheckCircle2,
  FileCheck,
  GitPullRequestArrow,
  LayoutDashboard,
  Network,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal
} from "lucide-react";
import "./styles.css";

const API = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

type RouteKey =
  | "dashboard"
  | "findings"
  | "assets"
  | "graph"
  | "attackPaths"
  | "remediation"
  | "simulations"
  | "workflows"
  | "virtual"
  | "agentic"
  | "policies"
  | "reports"
  | "audit"
  | "ops";

const nav: Array<{ key: RouteKey; label: string; icon: React.ComponentType<{ size?: number }> }> = [
  { key: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { key: "findings", label: "Findings", icon: ShieldAlert },
  { key: "assets", label: "Assets", icon: Boxes },
  { key: "graph", label: "Asset Graph", icon: Network },
  { key: "attackPaths", label: "Attack Paths", icon: Network },
  { key: "remediation", label: "Remediation", icon: GitPullRequestArrow },
  { key: "simulations", label: "Simulations", icon: Activity },
  { key: "workflows", label: "Approvals", icon: CheckCircle2 },
  { key: "virtual", label: "Virtual Patch", icon: ShieldCheck },
  { key: "agentic", label: "Agentic", icon: Bot },
  { key: "policies", label: "Policies", icon: SlidersHorizontal },
  { key: "reports", label: "Reports", icon: FileCheck },
  { key: "audit", label: "Audit", icon: ScrollText },
  { key: "ops", label: "Operations", icon: Activity }
];

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: { "content-type": "application/json", ...(options?.headers || {}) }
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

function useApi<T>(path: string, refresh = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    api<T>(path)
      .then((result) => active && setData(result))
      .catch((err) => active && setError(String(err)));
    return () => {
      active = false;
    };
  }, [path, refresh]);
  return { data, error };
}

function App() {
  const [route, setRoute] = useState<RouteKey>("dashboard");
  const [refresh, setRefresh] = useState(0);
  const Page = useMemo(() => pages[route], [route]);
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span>R</span><strong>Remediation Twin</strong></div>
        <nav>
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <button className={route === item.key ? "active" : ""} key={item.key} onClick={() => setRoute(item.key)}>
                <Icon size={18} /> {item.label}
              </button>
            );
          })}
        </nav>
      </aside>
      <main>
        <Page refresh={refresh} bump={() => setRefresh((value) => value + 1)} />
      </main>
    </div>
  );
}

function Header({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: React.ReactNode }) {
  return (
    <header className="header">
      <div>
        <p>{eyebrow}</p>
        <h1>{title}</h1>
        <span>{description}</span>
      </div>
      <div className="actions">{children}</div>
    </header>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return <div className="panel metric"><span>{label}</span><strong>{value}</strong></div>;
}

function Badge({ value }: { value: string }) {
  return <span className="badge">{value}</span>;
}

function Json({ value }: { value: unknown }) {
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

function Dashboard({ refresh, bump }: PageProps) {
  const { data } = useApi<any>("/api/dashboard", refresh);
  return (
    <>
      <Header eyebrow="Enterprise command center" title="Dashboard" description="Risk, remediation, simulation, approval, and evidence posture.">
        <button onClick={async () => { await api("/api/mock-ingest", { method: "POST", body: "{}" }); bump(); }}>Load prototype data</button>
      </Header>
      <section className="grid cols-4">
        <Metric label="Open Findings" value={data?.counts?.open_findings ?? 0} />
        <Metric label="Assets" value={data?.counts?.assets ?? 0} />
        <Metric label="Actions" value={data?.counts?.remediation_actions ?? 0} />
        <Metric label="Simulation Coverage" value={`${data?.risk?.simulation_coverage ?? 0}%`} />
      </section>
      <Table title="Top Findings" rows={data?.top_findings || []} columns={["title", "severity", "business_risk_score", "status"]} />
    </>
  );
}

function Findings({ refresh }: PageProps) {
  const { data } = useApi<any>("/api/findings", refresh);
  return <><Header eyebrow="Normalized backlog" title="Findings" description="Canonical findings after ingestion, deduplication, risk scoring, and asset mapping." /><Table rows={data?.findings || []} columns={["title", "severity", "business_risk_score", "source", "status"]} /></>;
}

function Assets({ refresh }: PageProps) {
  const { data } = useApi<any>("/api/assets", refresh);
  return <><Header eyebrow="Asset inventory" title="Assets" description="Systems, services, owners, exposure, criticality, and data sensitivity." /><Table rows={data?.assets || []} columns={["name", "type", "environment", "criticality", "data_sensitivity", "internet_exposure"]} /></>;
}

function Graph({ refresh }: PageProps) {
  const { data } = useApi<any>("/api/asset-graph", refresh);
  return <><Header eyebrow="Blast radius" title="Asset Graph" description="Dependency and attack-path graph for remediation impact decisions." /><section className="grid cols-3"><Metric label="Assets" value={data?.summary?.assets ?? 0} /><Metric label="Edges" value={data?.summary?.edges ?? 0} /><Metric label="Exposed" value={data?.summary?.exposed_assets ?? 0} /></section><Json value={data} /></>;
}

function AttackPaths({ refresh, bump }: PageProps) {
  const { data } = useApi<any>("/api/attack-paths", refresh);
  const model = data?.attack_paths;
  return (
    <>
      <Header eyebrow="Vulnerability chaining" title="Attack Path Analytics" description="Scanner-normalized attack paths with difficulty and before/after remediation risk.">
        <button onClick={async () => { await api("/api/attack-paths", { method: "POST", body: JSON.stringify({ action: "snapshot" }) }); bump(); }}>Snapshot analytics</button>
      </Header>
      <section className="grid cols-4">
        <Metric label="Attack Paths" value={model?.summary?.attack_paths ?? 0} />
        <Metric label="Critical Paths" value={model?.summary?.critical_paths ?? 0} />
        <Metric label="Before Risk" value={`${model?.summary?.average_before_risk ?? 0}%`} />
        <Metric label="After Risk" value={`${model?.summary?.average_after_risk ?? 0}%`} />
      </section>
      <AttackGraphView model={model} />
      <ChainGraphView chains={model?.vulnerability_chain_graph || []} />
      <Table rows={model?.paths || []} columns={["name", "difficulty", "before_remediation_risk", "after_remediation_risk", "risk_delta", "priority"]} />
      <Json value={model?.construction_method || {}} />
    </>
  );
}

function AttackGraphView({ model }: { model: any }) {
  const nodes = model?.attack_graph?.nodes || [];
  const edges = model?.attack_graph?.edges || [];
  const entries = nodes.filter((node: any) => node.kind === "entry").slice(0, 5);
  const targets = nodes.filter((node: any) => node.kind === "crown_jewel" || node.kind === "breaker").slice(0, 6);
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Attack Path Graph</h2>
          <p>Entry assets, reachable services, exploit preconditions, crown-jewel targets, and breaker controls.</p>
        </div>
        <Badge value={`${nodes.length} nodes / ${edges.length} edges`} />
      </div>
      <div className="attack-graph-board">
        <div className="graph-column">
          <span>Entry</span>
          {entries.map((node: any) => <GraphNode key={node.id} node={node} />)}
        </div>
        <div className="graph-column wide">
          <span>Reachability and exploit edges</span>
          {edges.slice(0, 10).map((edge: any) => (
            <div className={`graph-link ${edge.relation}`} key={edge.id}>
              <strong>{nodeLabel(edge.from, nodes)}</strong>
              <span>{edge.label}</span>
              <strong>{nodeLabel(edge.to, nodes)}</strong>
            </div>
          ))}
        </div>
        <div className="graph-column">
          <span>Targets and breakers</span>
          {targets.map((node: any) => <GraphNode key={node.id} node={node} />)}
        </div>
      </div>
    </section>
  );
}

function ChainGraphView({ chains }: { chains: any[] }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Vulnerability Chaining Graph</h2>
          <p>Ordered exploit chains with scanner source, technique, difficulty, residual risk, and the control that breaks the path.</p>
        </div>
        <Badge value={`${chains.length} chains`} />
      </div>
      <div className="chain-grid">
        {chains.map((chain) => (
          <article className="chain-card" key={chain.path_id}>
            <div className="chain-head">
              <div>
                <strong>{chain.path_name}</strong>
                <span>{chain.before_remediation_risk}% before / {chain.after_remediation_risk}% after</span>
              </div>
              <Badge value={chain.difficulty} />
            </div>
            <div className="chain-rail">
              {(chain.nodes || []).map((node: any, index: number) => (
                <div className="chain-node-wrap" key={`${chain.path_id}-${node.id}-${index}`}>
                  <GraphNode node={node} compact />
                  {index < chain.nodes.length - 1 && <div className="chain-arrow">risk transfer</div>}
                </div>
              ))}
            </div>
          </article>
        ))}
        {chains.length === 0 && <div className="empty">No attack paths yet. Load findings or ingest scanner data.</div>}
      </div>
    </section>
  );
}

function GraphNode({ node, compact = false }: { node: any; compact?: boolean }) {
  return (
    <div className={`graph-node ${node.kind} ${compact ? "compact" : ""}`}>
      <small>{String(node.kind || "node").replace("_", " ")}</small>
      <strong>{node.label}</strong>
      <span>{node.group} | {node.risk}%</span>
    </div>
  );
}

function nodeLabel(id: string, nodes: any[]) {
  return nodes.find((node) => node.id === id)?.label || id.replace(/^(asset|finding|breaker):/, "");
}

function Remediation({ refresh, bump }: PageProps) {
  const { data } = useApi<any>("/api/remediation-actions", refresh);
  const first = data?.actions?.[0]?._id;
  return (
    <>
      <Header eyebrow="Action queue" title="Remediation" description="Simulate, plan, approve, and evidence remediation actions before execution.">
        <button disabled={!first} onClick={async () => { await api(`/api/remediation-actions/${first}/simulate`, { method: "POST", body: "{}" }); bump(); }}>Simulate first</button>
        <button disabled={!first} onClick={async () => { await api(`/api/remediation-actions/${first}/plan`, { method: "POST", body: "{}" }); bump(); }}>Plan first</button>
        <button disabled={!first} onClick={async () => { await api(`/api/remediation-actions/${first}/workflow`, { method: "POST", body: "{}" }); bump(); }}>Approve first</button>
      </Header>
      <Table rows={data?.actions || []} columns={["title", "action_type", "status", "expected_risk_reduction"]} />
    </>
  );
}

function Simulations({ refresh }: PageProps) {
  const { data } = useApi<any>("/api/simulations", refresh);
  return <><Header eyebrow="What-if execution" title="Simulations" description="Risk reduction, operational risk, confidence, blast radius, and rollback requirements." /><Table rows={data?.simulations || []} columns={["type", "status", "confidence", "risk_reduction_estimate", "operational_risk"]} /></>;
}

function Workflows({ refresh }: PageProps) {
  const { data } = useApi<any>("/api/workflows", refresh);
  return <><Header eyebrow="Human control" title="Approvals" description="Security, service-owner, risk-owner, and CAB workflow state." /><Table rows={data?.workflows || []} columns={["title", "status", "created_at"]} /></>;
}

function VirtualPatch({ refresh, bump }: PageProps) {
  const { data } = useApi<any>("/api/virtual-patching", refresh);
  return (
    <>
      <Header eyebrow="Compensating control plane" title="Virtual Patching" description="Protect exposed paths before permanent remediation is safe.">
        <button onClick={async () => { await api("/api/virtual-patching", { method: "POST", body: "{}" }); bump(); }}>Activate controls</button>
      </Header>
      <section className="grid cols-3">
        <Metric label="Candidates" value={data?.summary?.virtual_patch_candidates ?? 0} />
        <Metric label="Path Breakers" value={data?.summary?.path_breaker_candidates ?? 0} />
        <Metric label="Policies" value={data?.summary?.active_policies ?? 0} />
      </section>
      <Table rows={data?.candidates || []} columns={["asset", "control", "score"]} />
    </>
  );
}

function Agentic({ refresh, bump }: PageProps) {
  const { data } = useApi<any>("/api/agentic", refresh);
  const agentic = data?.agentic;
  return (
    <>
      <Header eyebrow="Model-agnostic autonomy" title="Agentic Orchestrator" description="Plan with any LLM, SLM, gateway, or deterministic fallback while keeping execution governed.">
        <button onClick={async () => { await api("/api/agentic", { method: "POST", body: JSON.stringify({ goal: "virtual_patch", prompt: "Plan safest next actions with virtual patching and path breakers.", dry_run: true }) }); bump(); }}>Run agent plan</button>
      </Header>
      <section className="grid cols-4">
        <Metric label="Readiness" value={`${agentic?.readiness_score ?? 0}%`} />
        <Metric label="Status" value={agentic?.status ?? "unknown"} />
        <Metric label="Tools" value={agentic?.tool_registry?.length ?? 0} />
        <Metric label="Runs" value={agentic?.recent_agent_runs?.length ?? 0} />
      </section>
      <Table title="Model Providers" rows={agentic?.providers || []} columns={["provider", "model", "configured", "purpose"]} />
      <Table title="Tool Registry" rows={agentic?.tool_registry || []} columns={["name", "mode", "risk", "purpose"]} />
    </>
  );
}

function Policies({ refresh }: PageProps) {
  const { data } = useApi<any>("/api/policies", refresh);
  return <><Header eyebrow="Governance" title="Policies" description="Freeze windows, evidence gates, virtual patches, path breakers, and execution guardrails." /><Table rows={data?.policies || []} columns={["name", "policy_type", "enabled", "created_at"]} /></>;
}

function Reports({ refresh }: PageProps) {
  const { data } = useApi<any>("/api/reports", refresh);
  return <><Header eyebrow="Evidence and executive reporting" title="Reports" description="Report snapshots, agent plans, continuous simulation, and maturity exports." /><Table rows={data?.reports || []} columns={["name", "type", "created_by", "created_at"]} /></>;
}

function Audit({ refresh }: PageProps) {
  const { data } = useApi<any>("/api/audit", refresh);
  return <><Header eyebrow="Audit trail" title="Audit" description="Tenant-scoped audit records for ingestion, simulation, policy, connector, and agent events." /><Table rows={data?.audit || []} columns={["actor", "action", "entity_type", "created_at"]} /></>;
}

function Ops({ refresh, bump }: PageProps) {
  const { data } = useApi<any>("/api/observability", refresh);
  return <><Header eyebrow="Production operations" title="Operations" description="Worker runs, connector dry-runs, observability, and alert readiness."><button onClick={async () => { await api("/api/workers/run", { method: "POST", body: JSON.stringify({ lane: "simulation", limit: 3 }) }); bump(); }}>Run worker</button></Header><Json value={data} /></>;
}

function Table({ title, rows, columns }: { title?: string; rows: any[]; columns: string[] }) {
  return (
    <section className="panel">
      {title && <h2>{title}</h2>}
      <table>
        <thead><tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr></thead>
        <tbody>
          {rows.length === 0 && <tr><td colSpan={columns.length}>No records yet.</td></tr>}
          {rows.map((row, index) => (
            <tr key={row._id || row.id || index}>
              {columns.map((column) => <td key={column}>{typeof row[column] === "boolean" ? <Badge value={String(row[column])} /> : String(row[column] ?? "")}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

type PageProps = { refresh: number; bump: () => void };
const pages: Record<RouteKey, React.ComponentType<PageProps>> = { dashboard: Dashboard, findings: Findings, assets: Assets, graph: Graph, attackPaths: AttackPaths, remediation: Remediation, simulations: Simulations, workflows: Workflows, virtual: VirtualPatch, agentic: Agentic, policies: Policies, reports: Reports, audit: Audit, ops: Ops };

createRoot(document.getElementById("root")!).render(<App />);
