import { useMemo, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

type GraphNode = {
  id: string;
  label: string;
  kind: string;
  group?: string;
  risk?: number;
  impactScore?: number;
  impact_score?: number;
  preRemediationRisk?: number;
  pre_remediation_risk?: number;
  postRemediationRisk?: number;
  post_remediation_risk?: number;
  pathIds?: string[];
  path_ids?: string[];
  maturity?: number;
  difficulty?: string;
  metadata?: Record<string, unknown>;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  label?: string;
  kind?: string;
  weight?: number;
  confidence?: number;
};

const nodeTypes = { enterprise: EnterpriseNode };

export function GraphCanvas({ title, description, nodes = [], edges = [], mode }: { title: string; description: string; nodes?: GraphNode[]; edges?: GraphEdge[]; mode: "asset" | "attack" | "chain" }) {
  const [kind, setKind] = useState("all");
  const [riskFloor, setRiskFloor] = useState(0);
  const [layout, setLayout] = useState<"layered" | "radial">("layered");
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const kinds = useMemo(() => ["all", ...Array.from(new Set(nodes.map((node) => node.kind))).sort()], [nodes]);
  const visible = useMemo(() => {
    const filteredNodes = nodes.filter((node) => (kind === "all" || node.kind === kind) && Number(node.risk ?? 0) >= riskFloor);
    const nodeIds = new Set(filteredNodes.map((node) => node.id));
    return { nodes: filteredNodes, edges: edges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)) };
  }, [edges, kind, nodes, riskFloor]);
  const flowNodes: Node[] = useMemo(() => layoutNodes(visible.nodes, visible.edges, layout, mode), [layout, mode, visible.edges, visible.nodes]);
  const flowEdges: Edge[] = useMemo(() => visible.edges.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label,
    type: "smoothstep",
    animated: edge.kind === "exploit_precondition" || edge.kind === "breaker",
    markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor(edge.kind) },
    style: { stroke: edgeColor(edge.kind), strokeWidth: Math.max(1.5, Math.min(5, Number(edge.weight ?? 20) / 20)) },
    labelStyle: { fill: "#2e2e38", fontWeight: 800, fontSize: 11 },
    labelBgStyle: { fill: "#fff7b8", fillOpacity: 0.95 }
  })), [visible.edges]);
  const exportHref = `data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify({ nodes: visible.nodes, edges: visible.edges }, null, 2))}`;

  return (
    <section className="panel graph-panel">
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
        <span className="badge">{visible.nodes.length} nodes / {visible.edges.length} edges</span>
      </div>
      <div className="graph-toolbar">
        <select value={kind} onChange={(event) => setKind(event.target.value)}>
          {kinds.map((item) => <option key={item} value={item}>{item.replace("_", " ")}</option>)}
        </select>
        <select value={layout} onChange={(event) => setLayout(event.target.value as "layered" | "radial")}>
          <option value="layered">Layered</option>
          <option value="radial">Radial</option>
        </select>
        <label className="graph-slider">
          Risk
          <input type="range" min="0" max="100" step="10" value={riskFloor} onChange={(event) => setRiskFloor(Number(event.target.value))} />
          <strong>{riskFloor}+</strong>
        </label>
        <a className="button-link" href={exportHref} download={`${mode}-graph.json`}>Export graph</a>
      </div>
      <div className="flow-shell">
        <ReactFlow nodes={flowNodes} edges={flowEdges} nodeTypes={nodeTypes} fitView minZoom={0.25} maxZoom={1.8} onNodeClick={(_, node) => setSelected(node.data.raw as GraphNode)}>
          <MiniMap nodeColor={(node) => kindColor(String(node.data.kind))} maskColor="rgba(26,26,36,0.08)" pannable zoomable />
          <Controls showInteractive={false} />
          <Background color="#d9d9cf" gap={22} variant={BackgroundVariant.Dots} />
        </ReactFlow>
      </div>
      <div className="graph-inspector">
        {selected ? (
          <>
            <strong>{selected.label}</strong>
            <span>{selected.kind.replace("_", " ")} / {selected.group ?? "ungrouped"} / impact {selected.impactScore ?? selected.impact_score ?? selected.risk ?? 0}</span>
            <span>pre {selected.preRemediationRisk ?? selected.pre_remediation_risk ?? selected.risk ?? 0}% / post {selected.postRemediationRisk ?? selected.post_remediation_risk ?? selected.risk ?? 0}% / paths {(selected.pathIds ?? selected.path_ids ?? []).length || 1}</span>
            <span>{selected.maturity !== undefined ? `${selected.maturity}% maturity` : selected.difficulty ?? "difficulty pending"}</span>
          </>
        ) : (
          <span>Select a graph node to inspect ownership, risk, difficulty, and maturity context.</span>
        )}
      </div>
    </section>
  );
}

function EnterpriseNode({ data }: NodeProps) {
  const risk = Number(data.risk ?? 0);
  const impact = Number(data.impactScore ?? data.impact_score ?? risk);
  return (
    <div className={`flow-node ${data.kind}`}>
      <Handle type="target" position={Position.Left} />
      <small>{String(data.kind).replace("_", " ")}</small>
      <strong>{String(data.label)}</strong>
      <span>{String(data.group ?? "graph")} / impact {impact}</span>
      <span>pre {String(data.preRemediationRisk ?? data.pre_remediation_risk ?? risk)}% / post {String(data.postRemediationRisk ?? data.post_remediation_risk ?? risk)}%</span>
      <div className="risk-meter"><i style={{ width: `${Math.min(100, impact)}%` }} /></div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

function layoutNodes(nodes: GraphNode[], edges: GraphEdge[], layout: "layered" | "radial", mode: string): Node[] {
  const layers = layerNodes(nodes, edges, mode);
  if (layout === "radial") {
    const radius = Math.max(220, nodes.length * 18);
    return nodes.map((node, index) => {
      const angle = (index / Math.max(1, nodes.length)) * Math.PI * 2;
      return toFlowNode(node, { x: Math.cos(angle) * radius + radius, y: Math.sin(angle) * radius + radius * 0.7 });
    });
  }
  return nodes.map((node) => {
    const layer = layers.get(node.id) ?? 1;
    const siblings = nodes.filter((candidate) => (layers.get(candidate.id) ?? 1) === layer);
    const index = siblings.findIndex((candidate) => candidate.id === node.id);
    return toFlowNode(node, { x: layer * 330, y: index * 145 + 40 });
  });
}

function toFlowNode(node: GraphNode, position: { x: number; y: number }): Node {
  return { id: node.id, type: "enterprise", position, data: { ...node, raw: node } };
}

function layerNodes(nodes: GraphNode[], edges: GraphEdge[], mode: string) {
  const layer = new Map<string, number>();
  for (const node of nodes) {
    if (["internet_exposed", "entry"].includes(node.kind)) layer.set(node.id, 0);
    else if (["finding", "asset"].includes(node.kind)) layer.set(node.id, mode === "asset" ? 1 : 2);
    else if (["production", "crown_jewel"].includes(node.kind)) layer.set(node.id, 3);
    else if (node.kind === "breaker") layer.set(node.id, 4);
    else layer.set(node.id, 1);
  }
  for (let pass = 0; pass < 3; pass += 1) {
    for (const edge of edges) {
      const sourceLayer = layer.get(edge.source) ?? 0;
      layer.set(edge.target, Math.max(layer.get(edge.target) ?? 0, sourceLayer + 1));
    }
  }
  return layer;
}

function edgeColor(kind?: string) {
  if (kind === "breaker") return "#067647";
  if (kind === "exploit_precondition") return "#b42318";
  if (kind === "potential_reachability" || kind === "reachability") return "#9a6b00";
  return "#747480";
}

function kindColor(kind: string) {
  if (kind === "breaker") return "#067647";
  if (kind === "finding") return "#b42318";
  if (kind === "crown_jewel" || kind === "production") return "#9a6b00";
  if (kind === "entry" || kind === "internet_exposed") return "#ffe600";
  return "#747480";
}
