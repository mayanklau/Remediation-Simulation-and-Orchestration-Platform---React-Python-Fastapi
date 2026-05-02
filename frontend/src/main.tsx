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
  Search,
  ShieldAlert,
  ShieldCheck,
  Shield,
  Sparkles,
  SlidersHorizontal
} from "lucide-react";
import { GraphCanvas } from "./GraphCanvas";
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
  | "integrations"
  | "policies"
  | "reports"
  | "audit"
  | "ops";

const navGroups: Array<{ label: string; items: Array<{ key: RouteKey; label: string; icon: React.ComponentType<{ size?: number }> }> }> = [
  {
    label: "Command",
    items: [
      { key: "dashboard", label: "Dashboard", icon: LayoutDashboard },
      { key: "findings", label: "Findings", icon: ShieldAlert },
      { key: "assets", label: "Assets", icon: Boxes },
      { key: "graph", label: "Asset Graph", icon: Network },
      { key: "attackPaths", label: "Attack Paths", icon: Network }
    ]
  },
  {
    label: "Remediate",
    items: [
      { key: "remediation", label: "Remediation", icon: GitPullRequestArrow },
      { key: "simulations", label: "Simulations", icon: Activity },
      { key: "workflows", label: "Approvals", icon: CheckCircle2 },
      { key: "virtual", label: "Virtual Patch", icon: ShieldCheck },
      { key: "agentic", label: "Agentic", icon: Bot },
      { key: "integrations", label: "Integrations", icon: Activity }
    ]
  },
  {
    label: "Govern",
    items: [
      { key: "policies", label: "Policies", icon: SlidersHorizontal },
      { key: "reports", label: "Reports", icon: FileCheck },
      { key: "audit", label: "Audit", icon: ScrollText },
      { key: "ops", label: "Operations", icon: Activity }
    ]
  }
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
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    api<T>(path)
      .then((result) => active && setData(result))
      .catch((err) => active && setError(String(err)))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [path, refresh]);
  return { data, error, loading };
}

function App() {
  const [route, setRoute] = useState<RouteKey>("dashboard");
  const [refresh, setRefresh] = useState(0);
  const Page = useMemo(() => pages[route], [route]);
  const activeLabel = navGroups.flatMap((group) => group.items).find((item) => item.key === route)?.label || "Dashboard";
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span>EY</span>
          <div>
            <strong>EY Remediation Twin</strong>
            <small>Attack-path command center</small>
          </div>
        </div>
        <div className="side-card">
          <div><Shield size={16} /><strong>EY Control Tower</strong></div>
          <p>Tenant guarded, simulation first, evidence always ready.</p>
        </div>
        <nav>
          {navGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <span>{group.label}</span>
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <button className={route === item.key ? "active" : ""} key={item.key} onClick={() => setRoute(item.key)}>
                    <Icon size={18} /> {item.label}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>
      <main>
        <div className="topbar">
          <div className="search-box"><Search size={17} /><span>Search findings, assets, paths, controls</span></div>
          <div className="topbar-actions">
            <span className="health-dot">Live</span>
            <span className="pill"><Sparkles size={14} /> {activeLabel}</span>
          </div>
        </div>
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

function DataStatus({ loading, error }: { loading?: boolean; error?: string | null }) {
  if (loading) return <div className="data-state loading">Loading live platform state...</div>;
  if (error) return <div className="data-state error">Unable to load data: {error}</div>;
  return null;
}

function Dashboard({ refresh, bump }: PageProps) {
  const { data, loading, error } = useApi<any>("/api/dashboard", refresh);
  return (
    <>
      <Header eyebrow="Enterprise command center" title="Dashboard" description="Risk, remediation, simulation, approval, and evidence posture.">
        <button onClick={async () => { await api("/api/mock-ingest", { method: "POST", body: "{}" }); bump(); }}>Load prototype data</button>
      </Header>
      <DataStatus loading={loading} error={error} />
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
  const { data, loading, error } = useApi<any>("/api/findings", refresh);
  return <><Header eyebrow="Normalized backlog" title="Findings" description="Canonical findings after ingestion, deduplication, risk scoring, and asset mapping." /><DataStatus loading={loading} error={error} /><Table rows={data?.findings || []} columns={["title", "severity", "business_risk_score", "source", "status"]} /></>;
}

function Assets({ refresh }: PageProps) {
  const { data, loading, error } = useApi<any>("/api/assets", refresh);
  return <><Header eyebrow="Asset inventory" title="Assets" description="Systems, services, owners, exposure, criticality, and data sensitivity." /><DataStatus loading={loading} error={error} /><Table rows={data?.assets || []} columns={["name", "type", "environment", "criticality", "data_sensitivity", "internet_exposure"]} /></>;
}

function Graph({ refresh }: PageProps) {
  const { data, loading, error } = useApi<any>("/api/asset-graph", refresh);
  return (
    <>
      <Header eyebrow="Blast radius" title="Asset Graph" description="Dependency and attack-path graph for remediation impact decisions." />
      <DataStatus loading={loading} error={error} />
      <section className="grid cols-3">
        <Metric label="Assets" value={data?.summary?.assets ?? 0} />
        <Metric label="Edges" value={data?.summary?.edges ?? 0} />
        <Metric label="Exposed" value={data?.summary?.exposed_assets ?? 0} />
      </section>
      <GraphCanvas
        title="Interactive Enterprise Asset Graph"
        description="Real graph-library visualization with pan, zoom, minimap, risk filtering, dependency edges, internet exposure, production concentration, and graph JSON export."
        mode="asset"
        nodes={data?.library_graph?.nodes || []}
        edges={data?.library_graph?.edges || []}
      />
      <Json value={data?.library_graph || {}} />
    </>
  );
}

function AttackPaths({ refresh, bump }: PageProps) {
  const { data, loading, error } = useApi<any>("/api/attack-paths", refresh);
  const model = data?.attack_paths;
  return (
    <>
      <Header eyebrow="Vulnerability chaining" title="Attack Path Analytics" description="Scanner-normalized attack paths with difficulty and before/after remediation risk.">
        <button onClick={async () => { await api("/api/attack-paths", { method: "POST", body: JSON.stringify({ action: "snapshot" }) }); bump(); }}>Snapshot analytics</button>
      </Header>
      <DataStatus loading={loading} error={error} />
      <section className="grid cols-4">
        <Metric label="Attack Paths" value={model?.summary?.attack_paths ?? 0} />
        <Metric label="Critical Paths" value={model?.summary?.critical_paths ?? 0} />
        <Metric label="Before Risk" value={`${model?.summary?.average_before_risk ?? 0}%`} />
        <Metric label="After Risk" value={`${model?.summary?.average_after_risk ?? 0}%`} />
      </section>
      <section className="grid cols-2">
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>Scanner Coverage</h2>
              <p>Readiness by scanner family for mapping, exploit signal, remediation signal, and graph construction.</p>
            </div>
            <Badge value={`${model?.subject_maturity?.score ?? 0}% subject`} />
          </div>
          <table>
            <thead><tr><th>family</th><th>findings</th><th>mapping</th><th>exploit</th><th>remediation</th></tr></thead>
            <tbody>
              {(model?.scanner_coverage || []).map((coverage: any) => (
                <tr key={coverage.family}>
                  <td>{coverage.family}</td>
                  <td>{coverage.findings}</td>
                  <td>{coverage.asset_mapping_coverage}%</td>
                  <td>{coverage.exploit_signal_coverage}%</td>
                  <td>{coverage.remediation_signal_coverage}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>Decision Readiness</h2>
              <p>Customer-ready path risk, escalation posture, and release confidence from real platform state.</p>
            </div>
            <Badge value={model?.decision_readiness?.recommended_decision || "needs_data"} />
          </div>
          <table>
            <tbody>
              <tr><td>customer_ready_paths</td><td>{model?.decision_readiness?.customer_ready_paths ?? 0}</td></tr>
              <tr><td>executive_escalations</td><td>{model?.decision_readiness?.immediate_executive_escalations ?? 0}</td></tr>
              <tr><td>average_difficulty</td><td>{model?.decision_readiness?.average_difficulty_score ?? 0}%</td></tr>
              <tr><td>average_likelihood</td><td>{model?.decision_readiness?.average_likelihood ?? 0}%</td></tr>
              <tr><td>business_impact</td><td>{model?.decision_readiness?.average_business_impact ?? 0}%</td></tr>
              <tr><td>release_confidence</td><td>{model?.development_maturity?.release_confidence ?? 0}%</td></tr>
            </tbody>
          </table>
        </section>
      </section>
      <GraphCanvas
        title="Interactive Attack Path Graph"
        description="Real graph-library representation of entry points, exploit preconditions, vulnerable findings, crown jewels, and path breaker controls with pan, zoom, minimap, risk filters, and export."
        mode="attack"
        nodes={model?.attack_graph?.library_graph?.nodes || []}
        edges={model?.attack_graph?.library_graph?.edges || []}
      />
      <AttackGraphView model={model} />
      <section className="grid cols-2">
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>Graph Algorithms</h2>
              <p>Shortest exploitable paths, k-hop blast radius, centrality, choke points, and crown-jewel exposure.</p>
            </div>
            <Badge value={`${model?.graph_algorithms?.choke_points?.length ?? 0} choke points`} />
          </div>
          <table>
            <thead><tr><th>name</th><th>hops</th><th>risk</th><th>difficulty</th></tr></thead>
            <tbody>
              {(model?.graph_algorithms?.shortest_exploitable_paths || []).map((path: any) => (
                <tr key={path.path_id}>
                  <td>{path.name}</td>
                  <td>{path.hops}</td>
                  <td>{path.risk}%</td>
                  <td><Badge value={path.difficulty} /></td>
                </tr>
              ))}
              {(model?.graph_algorithms?.shortest_exploitable_paths || []).length === 0 && <tr><td colSpan={4}>No paths yet.</td></tr>}
            </tbody>
          </table>
        </section>
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>Executive View</h2>
              <p>Business services at risk, risk reduced this week, blocked remediations, and attack paths closed.</p>
            </div>
            <Badge value={`${model?.executive_views?.attack_paths_closed ?? 0} closed`} />
          </div>
          <table>
            <tbody>
              <tr><td>risk_reduced_this_week</td><td>{model?.executive_views?.risk_reduced_this_week ?? 0}%</td></tr>
              <tr><td>blocked_remediations</td><td>{model?.executive_views?.blocked_remediations?.length ?? 0}</td></tr>
              <tr><td>top_service_at_risk</td><td>{model?.executive_views?.top_business_services_at_risk?.[0]?.service ?? "none"}</td></tr>
              <tr><td>narrative</td><td>{model?.executive_views?.narrative ?? "No executive view yet."}</td></tr>
            </tbody>
          </table>
        </section>
      </section>
      <ChainGraphView chains={model?.vulnerability_chain_graph || []} />
      <Table rows={model?.paths || []} columns={["name", "difficulty", "before_remediation_risk", "after_remediation_risk", "risk_delta", "priority", "customer_narrative"]} />
      <Json value={model?.construction_method || {}} />
    </>
  );
}

function AttackGraphView({ model }: { model: any }) {
  const [kind, setKind] = useState("all");
  const [zoom, setZoom] = useState("comfortable");
  const nodes = model?.attack_graph?.nodes || [];
  const edges = model?.attack_graph?.edges || [];
  const filteredNodes = kind === "all" ? nodes : nodes.filter((node: any) => node.kind === kind);
  const filteredNodeIds = new Set(filteredNodes.map((node: any) => node.id));
  const filteredEdges = edges.filter((edge: any) => kind === "all" || filteredNodeIds.has(edge.from) || filteredNodeIds.has(edge.to));
  const entries = filteredNodes.filter((node: any) => node.kind === "entry").slice(0, 5);
  const targets = filteredNodes.filter((node: any) => node.kind === "crown_jewel" || node.kind === "breaker").slice(0, 6);
  const exportHref = `data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(model?.attack_graph || {}, null, 2))}`;
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Attack Path Graph</h2>
          <p>Entry assets, reachable services, exploit preconditions, crown-jewel targets, and breaker controls.</p>
        </div>
        <Badge value={`${nodes.length} nodes / ${edges.length} edges`} />
      </div>
      <div className="graph-toolbar">
        <select value={kind} onChange={(event) => setKind(event.target.value)}>
          <option value="all">All nodes</option>
          <option value="entry">Entry</option>
          <option value="finding">Findings</option>
          <option value="crown_jewel">Crown jewels</option>
          <option value="breaker">Path breakers</option>
        </select>
        <select value={zoom} onChange={(event) => setZoom(event.target.value)}>
          <option value="compact">Compact</option>
          <option value="comfortable">Comfortable</option>
          <option value="expanded">Expanded</option>
        </select>
        <a className="button-link" href={exportHref} download="attack-path-graph.json">Export graph</a>
      </div>
      <div className={`attack-graph-board zoom-${zoom}`}>
        <div className="graph-column">
          <span>Entry</span>
          {entries.length === 0 && <div className="empty">No matching entry nodes.</div>}
          {entries.map((node: any) => <GraphNode key={node.id} node={node} />)}
        </div>
        <div className="graph-column wide">
          <span>Reachability and exploit edges</span>
          {filteredEdges.length === 0 && <div className="empty">No matching graph edges.</div>}
          {filteredEdges.slice(0, zoom === "expanded" ? 20 : 10).map((edge: any) => (
            <div className={`graph-link ${edge.relation}`} key={edge.id}>
              <strong>{nodeLabel(edge.from, nodes)}</strong>
              <span>{edge.label}</span>
              <strong>{nodeLabel(edge.to, nodes)}</strong>
            </div>
          ))}
        </div>
        <div className="graph-column">
          <span>Targets and breakers</span>
          {targets.length === 0 && <div className="empty">No matching target or breaker nodes.</div>}
          {targets.map((node: any) => <GraphNode key={node.id} node={node} />)}
        </div>
      </div>
    </section>
  );
}

function ChainGraphView({ chains }: { chains: any[] }) {
  const [difficulty, setDifficulty] = useState("all");
  const filteredChains = difficulty === "all" ? chains : chains.filter((chain) => chain.difficulty === difficulty);
  const exportHref = `data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(filteredChains, null, 2))}`;
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>Vulnerability Chaining Graph</h2>
          <p>Ordered exploit chains with scanner source, technique, difficulty, residual risk, and the control that breaks the path.</p>
        </div>
        <Badge value={`${chains.length} chains`} />
      </div>
      <div className="graph-toolbar">
        <select value={difficulty} onChange={(event) => setDifficulty(event.target.value)}>
          <option value="all">All difficulty</option>
          <option value="LOW">LOW</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="HIGH">HIGH</option>
          <option value="VERY_HIGH">VERY_HIGH</option>
        </select>
        <a className="button-link" href={exportHref} download="vulnerability-chains.json">Export chains</a>
      </div>
      <div className="chain-grid">
        {filteredChains.map((chain) => (
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
        {filteredChains.length === 0 && <div className="empty">No attack paths match this filter.</div>}
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

function Integrations({ refresh, bump }: PageProps) {
  const { data, loading, error } = useApi<any>("/api/connectors", refresh);
  const [form, setForm] = useState({
    provider: "custom-http",
    name: "Custom HTTP connector",
    category: "custom",
    auth_mode: "manual_secret_reference",
    endpoint: "https://example.internal/api",
    owner: "security-operations",
    scopes: "read",
    operation: "health_check",
    payload: '{ "mode": "manual_dry_run" }'
  });
  const templates = data?.templates || [];
  function applyTemplate(provider: string) {
    const template = templates.find((item: any) => item.provider === provider);
    setForm((current) => ({
      ...current,
      provider,
      name: `${provider} connector`,
      category: template?.category || "custom",
      scopes: (template?.scopes || ["read"]).join(","),
      operation: template?.operation || "health_check"
    }));
  }
  async function saveProfile() {
    await api("/api/connectors", { method: "POST", body: JSON.stringify(form) });
    bump();
  }
  async function runCheck(provider = form.provider, operation = form.operation) {
    let payload = {};
    try {
      payload = JSON.parse(form.payload || "{}");
    } catch {
      payload = { raw: form.payload };
    }
    await api("/api/connectors/live", { method: "POST", body: JSON.stringify({ provider, operation, dry_run: true, payload }) });
    bump();
  }
  return (
    <>
      <Header eyebrow="Manual connector factory" title="Integrations" description="Add any scanner, CMDB, ticketing, cloud, code, IAM, notification, or custom HTTP connector without code changes.">
        <button onClick={saveProfile}>Save profile</button>
        <button onClick={() => runCheck()}>Run dry check</button>
      </Header>
      <DataStatus loading={loading} error={error} />
      <section className="panel">
        <div className="connector-form-grid">
          <label><span>Template</span><select value={form.provider} onChange={(event) => applyTemplate(event.target.value)}>{templates.map((template: any) => <option key={template.provider} value={template.provider}>{template.provider}</option>)}</select></label>
          <label><span>Provider</span><input value={form.provider} onChange={(event) => setForm({ ...form, provider: event.target.value })} /></label>
          <label><span>Name</span><input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label>
          <label><span>Category</span><input value={form.category} onChange={(event) => setForm({ ...form, category: event.target.value })} /></label>
          <label><span>Auth mode</span><input value={form.auth_mode} onChange={(event) => setForm({ ...form, auth_mode: event.target.value })} /></label>
          <label><span>Endpoint</span><input value={form.endpoint} onChange={(event) => setForm({ ...form, endpoint: event.target.value })} /></label>
          <label><span>Owner</span><input value={form.owner} onChange={(event) => setForm({ ...form, owner: event.target.value })} /></label>
          <label><span>Scopes</span><input value={form.scopes} onChange={(event) => setForm({ ...form, scopes: event.target.value })} /></label>
          <label><span>Operation</span><input value={form.operation} onChange={(event) => setForm({ ...form, operation: event.target.value })} /></label>
        </div>
        <label className="wide-field"><span>Dry-run payload JSON</span><textarea value={form.payload} onChange={(event) => setForm({ ...form, payload: event.target.value })} /></label>
      </section>
      <Table title="Connector Profiles" rows={data?.profiles || []} columns={["name", "provider", "category", "auth_mode", "owner", "enabled"]} />
      <Table title="Recent Connector Runs" rows={data?.runs || []} columns={["provider", "operation", "status", "dry_run", "created_at"]} />
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
              {columns.map((column) => <td key={column}>{renderCell(row, column)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function renderCell(row: any, column: string) {
  const value = row[column];
  if (typeof value === "boolean") return <Badge value={String(value)} />;
  if ((column === "name" || column === "title") && (row._id || row.id)) {
    return <a className="drill-link" href={`#${row._id || row.id}`}>{String(value ?? "")}</a>;
  }
  return String(value ?? "");
}

type PageProps = { refresh: number; bump: () => void };
const pages: Record<RouteKey, React.ComponentType<PageProps>> = { dashboard: Dashboard, findings: Findings, assets: Assets, graph: Graph, attackPaths: AttackPaths, remediation: Remediation, simulations: Simulations, workflows: Workflows, virtual: VirtualPatch, agentic: Agentic, integrations: Integrations, policies: Policies, reports: Reports, audit: Audit, ops: Ops };

createRoot(document.getElementById("root")!).render(<App />);
