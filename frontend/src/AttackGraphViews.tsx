import type { CSSProperties } from "react";

type Path = {
  id: string;
  name: string;
  entry_asset: string;
  target_asset: string;
  chain: Array<{ title: string; source: string; technique: string; business_risk: number }>;
  difficulty: string;
  before_remediation_risk: number;
  after_remediation_risk: number;
  risk_delta: number;
  recommended_breakers: string[];
};

export function AttackGraphViews({ paths }: { paths: Path[] }) {
  const nodes = buildNodes(paths);
  const edges = paths.flatMap((path) => [
    { id: `${path.id}:reach`, from: path.entry_asset, to: path.target_asset, label: `${path.difficulty} / ${path.before_remediation_risk}%`, relation: "reachability" },
    { id: `${path.id}:breaker`, from: path.recommended_breakers?.[0] ?? "Path breaker", to: path.target_asset, label: `${path.risk_delta}% risk reduction`, relation: "breaker" }
  ]);
  const chains = paths.slice(0, 8);

  return (
    <>
      <section className="panel">
        <div style={styles.head}>
          <div>
            <h2>Attack Path Graph</h2>
            <p style={styles.copy}>Entry assets, reachable services, exploit preconditions, crown-jewel targets, and breaker controls.</p>
          </div>
          <span style={styles.badge}>{nodes.length} nodes / {edges.length} edges</span>
        </div>
        <div style={styles.board}>
          <div style={styles.column}>
            <span style={styles.columnTitle}>Entry</span>
            {nodes.filter((node) => node.kind === "entry").slice(0, 5).map((node) => <GraphNode key={node.id} node={node} />)}
          </div>
          <div style={styles.column}>
            <span style={styles.columnTitle}>Reachability and exploit edges</span>
            {edges.slice(0, 10).map((edge) => (
              <div key={edge.id} style={styles.edge}>
                <strong>{edge.from}</strong>
                <span style={edge.relation === "breaker" ? styles.breakerPill : styles.edgePill}>{edge.label}</span>
                <strong>{edge.to}</strong>
              </div>
            ))}
          </div>
          <div style={styles.column}>
            <span style={styles.columnTitle}>Targets and breakers</span>
            {nodes.filter((node) => node.kind === "target" || node.kind === "breaker").slice(0, 6).map((node) => <GraphNode key={node.id} node={node} />)}
          </div>
        </div>
      </section>

      <section className="panel">
        <div style={styles.head}>
          <div>
            <h2>Vulnerability Chaining Graph</h2>
            <p style={styles.copy}>Ordered exploit chain with scanner source, technique, difficulty, residual risk, and the control that breaks the path.</p>
          </div>
          <span style={styles.badge}>{chains.length} chains</span>
        </div>
        <div style={styles.chainGrid}>
          {chains.length === 0 && <div style={styles.empty}>No attack paths yet. Load prototype data or ingest scanner data.</div>}
          {chains.map((path) => (
            <article key={path.id} style={styles.chainCard}>
              <div style={styles.chainHead}>
                <div>
                  <strong>{path.name}</strong>
                  <div style={styles.copy}>{path.before_remediation_risk}% before / {path.after_remediation_risk}% after / {path.risk_delta}% reduced</div>
                </div>
                <span style={styles.badge}>{path.difficulty}</span>
              </div>
              <div style={styles.rail}>
                <GraphNode node={{ id: `${path.id}:entry`, label: path.entry_asset, kind: "entry", group: "Entry", risk: path.before_remediation_risk }} compact />
                {path.chain.map((step, index) => (
                  <div key={`${path.id}:${index}`} style={styles.chainStep}>
                    <span style={styles.arrow}>risk transfer</span>
                    <GraphNode node={{ id: `${path.id}:${index}`, label: step.title, kind: "finding", group: `${step.source} | ${step.technique}`, risk: step.business_risk }} compact />
                  </div>
                ))}
                <div style={styles.chainStep}>
                  <span style={styles.arrow}>target</span>
                  <GraphNode node={{ id: `${path.id}:target`, label: path.target_asset, kind: "target", group: "Crown jewel", risk: path.before_remediation_risk }} compact />
                </div>
                <div style={styles.chainStep}>
                  <span style={styles.arrow}>breaker</span>
                  <GraphNode node={{ id: `${path.id}:breaker`, label: path.recommended_breakers?.[0] ?? "Simulation-backed path breaker", kind: "breaker", group: "Control", risk: path.risk_delta }} compact />
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}

function GraphNode({ node, compact = false }: { node: { label: string; kind: string; group: string; risk: number }; compact?: boolean }) {
  const border = node.kind === "target" ? "#dc2626" : node.kind === "finding" ? "#d97706" : node.kind === "breaker" ? "#16a34a" : "#0f766e";
  return (
    <div style={{ ...styles.node, ...(compact ? styles.compactNode : {}), borderLeftColor: border }}>
      <small style={styles.nodeKind}>{node.kind}</small>
      <strong style={styles.nodeLabel}>{node.label}</strong>
      <span style={styles.copy}>{node.group} | {node.risk}%</span>
    </div>
  );
}

function buildNodes(paths: Path[]) {
  const map = new Map<string, { id: string; label: string; kind: string; group: string; risk: number }>();
  const upsert = (node: { id: string; label: string; kind: string; group: string; risk: number }) => {
    const existing = map.get(node.id);
    map.set(node.id, existing ? { ...existing, risk: Math.max(existing.risk, node.risk) } : node);
  };
  for (const path of paths) {
    upsert({ id: `entry:${path.entry_asset}`, label: path.entry_asset, kind: "entry", group: "Initial access", risk: path.before_remediation_risk });
    upsert({ id: `target:${path.target_asset}`, label: path.target_asset, kind: "target", group: "Crown jewel", risk: path.before_remediation_risk });
    upsert({ id: `breaker:${path.id}`, label: path.recommended_breakers?.[0] ?? "Simulation-backed path breaker", kind: "breaker", group: "Breaker", risk: path.risk_delta });
    path.chain.slice(0, 2).forEach((step, index) => upsert({ id: `finding:${path.id}:${index}`, label: step.title, kind: "finding", group: step.source, risk: step.business_risk }));
  }
  return [...map.values()].sort((left, right) => right.risk - left.risk).slice(0, 60);
}

const styles: Record<string, CSSProperties> = {
  head: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 14, marginBottom: 12 },
  copy: { color: "#64748b", fontSize: 12 },
  badge: { display: "inline-flex", borderRadius: 999, padding: "4px 8px", background: "#ccfbf1", color: "#115e59", fontSize: 12, fontWeight: 800, whiteSpace: "nowrap" },
  board: { display: "grid", gridTemplateColumns: "minmax(180px,.8fr) minmax(360px,1.5fr) minmax(220px,1fr)", gap: 14 },
  column: { display: "grid", gap: 10, alignContent: "start", minHeight: 220, border: "1px solid #d9e2ec", borderRadius: 8, padding: 12, background: "#f8fafc" },
  columnTitle: { color: "#64748b", fontSize: 12, fontWeight: 800, textTransform: "uppercase" },
  edge: { display: "grid", gridTemplateColumns: "minmax(120px,1fr) auto minmax(120px,1fr)", gap: 10, alignItems: "center", border: "1px solid #d9e2ec", borderRadius: 8, padding: 10, background: "#fff" },
  edgePill: { borderRadius: 999, padding: "5px 10px", background: "#e0f2fe", color: "#075985", fontSize: 12, fontWeight: 800, textAlign: "center" },
  breakerPill: { borderRadius: 999, padding: "5px 10px", background: "#dcfce7", color: "#166534", fontSize: 12, fontWeight: 800, textAlign: "center" },
  node: { display: "grid", gap: 5, minHeight: 86, border: "1px solid #cbd5e1", borderLeft: "5px solid #0f766e", borderRadius: 8, padding: 10, background: "#fff" },
  compactNode: { minWidth: 190, maxWidth: 240, minHeight: 104 },
  nodeKind: { color: "#64748b", fontSize: 11, fontWeight: 800, textTransform: "uppercase" },
  nodeLabel: { fontSize: 13, lineHeight: 1.25, overflowWrap: "anywhere" },
  chainGrid: { display: "grid", gap: 14 },
  chainCard: { border: "1px solid #d9e2ec", borderRadius: 8, padding: 14, background: "#fff" },
  chainHead: { display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 12 },
  rail: { display: "flex", gap: 10, overflowX: "auto", paddingBottom: 4 },
  chainStep: { display: "flex", alignItems: "center", gap: 10, flex: "0 0 auto" },
  arrow: { borderRadius: 999, padding: "5px 10px", background: "#dcfce7", color: "#166534", fontSize: 12, fontWeight: 800, whiteSpace: "nowrap" },
  empty: { border: "1px dashed #b6c2cf", borderRadius: 8, padding: 24, textAlign: "center", color: "#64748b", background: "#f8fafc" }
};
