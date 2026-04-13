"""
NEXUS SPECTER PRO — Attack Graph Engine
Builds and visualises multi-step attack paths from recon + vuln data.
Uses NetworkX for graph computation + exports D3.js interactive visualisation.
Computes: shortest paths, high-value targets, critical chokepoints, blast radius.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import json, logging
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.intelligence.attack_graph")

try:
    import networkx as nx
    NX_OK = True
except ImportError:
    NX_OK = False
    log.warning("[GRAPH] networkx not installed — run: pip install networkx")


# ── Node types ────────────────────────────────────────────────────────────────
NODE_TYPES = {
    "attacker":       {"color": "#FF003C", "shape": "diamond", "size": 30},
    "internet":       {"color": "#888888", "shape": "circle",  "size": 20},
    "host":           {"color": "#7B00FF", "shape": "circle",  "size": 18},
    "service":        {"color": "#00FFD4", "shape": "square",  "size": 14},
    "vulnerability":  {"color": "#FF8C00", "shape": "triangle","size": 16},
    "credential":     {"color": "#FFD700", "shape": "diamond", "size": 14},
    "domain_admin":   {"color": "#FF003C", "shape": "star",    "size": 35},
    "crown_jewel":    {"color": "#FF003C", "shape": "star",    "size": 40},
    "domain_controller":{"color":"#FF003C","shape":"square",   "size": 30},
    "workstation":    {"color": "#555555", "shape": "circle",  "size": 12},
    "database":       {"color": "#00FFD4", "shape": "cylinder","size": 20},
    "cloud_resource": {"color": "#7B00FF", "shape": "hexagon", "size": 18},
}

# ── Edge types ────────────────────────────────────────────────────────────────
EDGE_TYPES = {
    "exploits":          {"color": "#FF003C", "width": 3, "dashed": False},
    "lateral_move":      {"color": "#FF8C00", "width": 2, "dashed": False},
    "escalates_to":      {"color": "#FFD700", "width": 3, "dashed": False},
    "accesses":          {"color": "#00FFD4", "width": 1, "dashed": True},
    "authenticates":     {"color": "#7B00FF", "width": 2, "dashed": True},
    "network_reach":     {"color": "#555555", "width": 1, "dashed": True},
    "data_exfil":        {"color": "#FF003C", "width": 2, "dashed": False},
}

# ── MITRE ATT&CK technique weights (lower = easier) ──────────────────────────
TECHNIQUE_WEIGHTS = {
    "T1190":  1,   # Exploit Public-Facing Application
    "T1133":  2,   # External Remote Services
    "T1078":  1,   # Valid Accounts
    "T1110":  3,   # Brute Force
    "T1566":  2,   # Phishing
    "T1547":  2,   # Boot/Logon Autostart
    "T1068":  4,   # Exploitation for Privilege Escalation
    "T1548":  3,   # Abuse Elevation Control
    "T1550":  2,   # Use Alternate Auth Material (PtH)
    "T1021":  2,   # Remote Services
    "T1003":  2,   # OS Credential Dumping
    "T1484":  5,   # Domain Policy Modification
    "T1136":  3,   # Create Account
}


@dataclass
class AttackNode:
    node_id:    str
    label:      str
    node_type:  str
    ip:         str  = ""
    hostname:   str  = ""
    os:         str  = ""
    risk_score: int  = 0
    is_owned:   bool = False
    is_target:  bool = False
    metadata:   dict = field(default_factory=dict)


@dataclass
class AttackEdge:
    src:         str
    dst:         str
    edge_type:   str
    technique:   str  = ""   # MITRE T-ID
    weight:      int  = 1    # lower = easier
    description: str  = ""


@dataclass
class AttackPath:
    path_id:    str
    nodes:      list
    edges:      list
    total_weight: float
    techniques: list
    source:     str
    target:     str
    feasibility: str  = ""  # Easy / Medium / Hard
    description: str  = ""


class AttackGraph:
    """
    Attack Graph Engine for NEXUS SPECTER PRO.
    Ingests: recon data, vulnerability findings, AD intelligence.
    Computes:
    - Shortest / easiest paths from attacker to high-value targets
    - Critical chokepoints (nodes whose removal disconnects all paths)
    - Blast radius of each compromised node
    - D3.js + HTML interactive visualisation export
    - NetworkX JSON export for further analysis
    """

    def __init__(self, output_dir: str = "/tmp/nsp_graphs"):
        self.G          = nx.DiGraph() if NX_OK else None
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.nodes:     list[AttackNode] = []
        self.edges_:    list[AttackEdge] = []
        self._node_map: dict = {}

    # ── Graph construction ─────────────────────────────────────────────────────
    def add_node(self, node: AttackNode):
        self.nodes.append(node)
        self._node_map[node.node_id] = node
        if self.G is not None:
            self.G.add_node(
                node.node_id,
                label      = node.label,
                node_type  = node.node_type,
                ip         = node.ip,
                hostname   = node.hostname,
                risk_score = node.risk_score,
                is_owned   = node.is_owned,
                is_target  = node.is_target,
                **NODE_TYPES.get(node.node_type, {}),
            )

    def add_edge(self, edge: AttackEdge):
        self.edges_.append(edge)
        if self.G is not None:
            self.G.add_edge(
                edge.src, edge.dst,
                edge_type   = edge.edge_type,
                technique   = edge.technique,
                weight      = edge.weight,
                description = edge.description,
                **EDGE_TYPES.get(edge.edge_type, {}),
            )

    # ── Build from NSP data ───────────────────────────────────────────────────
    def build_from_mission_data(self, session_data: dict) -> "AttackGraph":
        """
        Auto-build graph from a NSP mission session dict.
        Reads: recon, enumeration, vuln_scan, post_exploit phases.
        """
        console.print("[bold #7B00FF]  🕸️  Building attack graph from mission data...[/bold #7B00FF]")

        # Attacker node (always present)
        self.add_node(AttackNode("ATTACKER", "Attacker", "attacker", is_owned=True))
        self.add_node(AttackNode("INTERNET", "Internet", "internet"))
        self.add_edge(AttackEdge("ATTACKER", "INTERNET", "network_reach", weight=0))

        target = session_data.get("target", "target")

        # ── From recon ──────────────────────────────────────────────────────
        recon = session_data.get("recon", {})

        # Subdomains → nodes
        subs = recon.get("subdomains", {}).get("all_subdomains", [])
        for i, sub in enumerate(subs[:20]):
            nid = f"HOST_{i}"
            self.add_node(AttackNode(nid, sub, "host", hostname=sub, risk_score=10))
            self.add_edge(AttackEdge("INTERNET", nid, "network_reach",
                                      technique="T1590", weight=1))

        # IPs from port scan
        port_data = recon.get("ports", {}).get("nmap_detailed", {})
        for j, host in enumerate(port_data.get("hosts", [])[:10]):
            ip  = host.get("addresses", [{}])[0].get("addr", f"10.0.0.{j}")
            nid = f"IP_{j}"
            self.add_node(AttackNode(nid, ip, "host", ip=ip, risk_score=15))
            self.add_edge(AttackEdge("INTERNET", nid, "network_reach",
                                      technique="T1046", weight=1))
            # Services as child nodes
            for port_info in host.get("ports", [])[:5]:
                svc_id = f"SVC_{j}_{port_info.get('portid','')}"
                svc_label = f"{port_info.get('service','')}:{port_info.get('portid','')}"
                self.add_node(AttackNode(svc_id, svc_label, "service"))
                self.add_edge(AttackEdge(nid, svc_id, "accesses", weight=1))

        # ── From vuln_scan ───────────────────────────────────────────────────
        vuln_data = session_data.get("vuln_scan", {})
        nuclei    = vuln_data.get("nuclei", {}).get("by_severity", {})

        vuln_nodes = []
        for sev in ["critical", "high", "medium"]:
            for k, f in enumerate(nuclei.get(sev, [])[:5]):
                v_nid = f"VULN_{sev}_{k}"
                host  = f.get("host", target)
                # Find parent host node
                parent = next((n.node_id for n in self.nodes
                               if n.ip == host or n.hostname == host), "INTERNET")
                self.add_node(AttackNode(
                    v_nid, f.get("name","Vuln")[:30], "vulnerability",
                    risk_score={"critical":90,"high":70,"medium":50}.get(sev,30),
                    metadata={"severity": sev, "cvss": f.get("cvss_score",0)},
                ))
                self.add_edge(AttackEdge(
                    parent, v_nid, "exploits",
                    technique="T1190",
                    weight=TECHNIQUE_WEIGHTS.get("T1190", 1),
                    description=f"{sev.upper()}: {f.get('name','')}",
                ))
                vuln_nodes.append(v_nid)

        # ── From post_exploit / BloodHound ───────────────────────────────────
        post = session_data.get("post_exploit", {})
        bh   = post.get("bloodhound", {})

        # Domain controllers
        for i, dc in enumerate(bh.get("dc_list", [])[:3]):
            dc_nid = f"DC_{i}"
            self.add_node(AttackNode(dc_nid, dc, "domain_controller",
                                     hostname=dc, risk_score=95, is_target=True))
            # Connect from vuln nodes via lateral movement
            for v_nid in vuln_nodes[:2]:
                self.add_edge(AttackEdge(
                    v_nid, dc_nid, "lateral_move",
                    technique="T1021", weight=3,
                    description="Lateral movement to DC",
                ))

        # Kerberoastable → credential escalation
        for i, acct in enumerate(bh.get("kerberoastable", [])[:3]):
            cred_nid = f"CRED_{i}"
            self.add_node(AttackNode(cred_nid, acct, "credential",
                                     risk_score=70))
            if vuln_nodes:
                self.add_edge(AttackEdge(
                    vuln_nodes[0], cred_nid, "escalates_to",
                    technique="T1558.003", weight=2,
                    description="Kerberoasting",
                ))
            # Credential → DC
            for dc_nid in [n.node_id for n in self.nodes
                           if n.node_type == "domain_controller"][:1]:
                self.add_edge(AttackEdge(
                    cred_nid, dc_nid, "authenticates",
                    technique="T1550", weight=2,
                    description="Pass-the-ticket",
                ))

        # Domain Admin crown jewel
        self.add_node(AttackNode("DA", "Domain Admin", "domain_admin",
                                  risk_score=100, is_target=True))
        for n in self.nodes:
            if n.node_type == "domain_controller":
                self.add_edge(AttackEdge(n.node_id, "DA", "escalates_to",
                                          technique="T1003", weight=2,
                                          description="DCSync → Domain Admin"))

        console.print(f"[bold #00FFD4]  ✅ Graph built: {len(self.nodes)} nodes, "
                       f"{len(self.edges_)} edges[/bold #00FFD4]")
        return self

    # ── Graph analysis ────────────────────────────────────────────────────────
    def find_attack_paths(self, source: str = "ATTACKER",
                           targets: list = None) -> list:
        """Find shortest weighted paths from attacker to all high-value targets."""
        if not NX_OK or self.G is None:
            return []

        target_nodes = targets or [
            n.node_id for n in self.nodes
            if n.node_type in ("domain_admin","crown_jewel","domain_controller")
        ]

        paths = []
        for tgt in target_nodes:
            try:
                path_nodes = nx.shortest_path(
                    self.G, source=source, target=tgt, weight="weight"
                )
                weight = nx.shortest_path_length(
                    self.G, source=source, target=tgt, weight="weight"
                )
                # Collect techniques
                techniques = []
                for i in range(len(path_nodes)-1):
                    e = self.G.edges[path_nodes[i], path_nodes[i+1]]
                    if e.get("technique"):
                        techniques.append(e["technique"])

                # Feasibility
                if weight <= 5:   feasibility = "Easy"
                elif weight <= 10: feasibility = "Medium"
                else:             feasibility = "Hard"

                path = AttackPath(
                    path_id    = f"PATH_{len(paths)+1}",
                    nodes      = path_nodes,
                    edges      = [(path_nodes[i], path_nodes[i+1])
                                  for i in range(len(path_nodes)-1)],
                    total_weight = weight,
                    techniques = list(set(techniques)),
                    source     = source,
                    target     = tgt,
                    feasibility= feasibility,
                    description= f"{source} → ... → {tgt} ({len(path_nodes)-1} hops)",
                )
                paths.append(path)

            except nx.NetworkXNoPath:
                log.debug(f"[GRAPH] No path to {tgt}")
            except nx.NodeNotFound:
                pass

        # Sort by weight (easiest first)
        paths.sort(key=lambda p: p.total_weight)
        return paths

    def find_chokepoints(self) -> list:
        """Find nodes whose removal disconnects attack paths (articulation points)."""
        if not NX_OK or self.G is None:
            return []
        undirected = self.G.to_undirected()
        choke_ids  = list(nx.articulation_points(undirected))
        chokepoints = [
            {"node_id": nid,
             "label":   self._node_map.get(nid, AttackNode(nid,"","")).label,
             "type":    self._node_map.get(nid, AttackNode(nid,"","host")).node_type}
            for nid in choke_ids
        ]
        log.info(f"[GRAPH] {len(chokepoints)} chokepoints found")
        return chokepoints

    def blast_radius(self, node_id: str) -> dict:
        """Compute what a compromised node can reach."""
        if not NX_OK or self.G is None:
            return {}
        reachable = nx.descendants(self.G, node_id)
        high_value = [
            nid for nid in reachable
            if self._node_map.get(nid, AttackNode(nid,"","")).node_type
            in ("domain_admin","crown_jewel","domain_controller","database")
        ]
        return {
            "compromised_node": node_id,
            "reachable_nodes":  len(reachable),
            "high_value_reachable": high_value,
            "blast_radius_pct": round(len(reachable)/max(len(self.G.nodes),1)*100, 1),
        }

    def _print_paths(self, paths: list):
        table = Table(
            title=f"[bold #7B00FF]🕸️  ATTACK PATHS — {len(paths)} found[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4", show_lines=True,
        )
        table.add_column("ID",          width=8)
        table.add_column("Feasibility", width=12)
        table.add_column("Hops",        width=6,  justify="right")
        table.add_column("Weight",      width=8,  justify="right")
        table.add_column("Target",      width=20)
        table.add_column("Path",        width=45)
        table.add_column("Techniques",  width=30)

        FEAS_COLOR = {"Easy":"[bold #FF003C]","Medium":"[bold #FFD700]","Hard":"[bold #00FFD4]"}
        for p in paths[:10]:
            fc = FEAS_COLOR.get(p.feasibility,"[white]")
            fe = fc.replace("[","[/")
            path_str = " → ".join(p.nodes)[-45:]
            table.add_row(
                p.path_id,
                f"{fc}{p.feasibility}{fe}",
                str(len(p.nodes)-1),
                str(round(p.total_weight,1)),
                p.target[-20:],
                path_str,
                ", ".join(p.techniques[:4]),
            )
        console.print(table)

    # ── Export: D3.js interactive HTML ───────────────────────────────────────
    def export_d3_html(self, paths: list = None,
                        filename: str = "attack_graph.html") -> Path:
        """
        Generate a self-contained interactive D3.js attack graph.
        Nodes are coloured by type, edges by technique.
        Click a node to see blast radius. Drag to reposition.
        """
        nodes_json = [
            {
                "id":        n.node_id,
                "label":     n.label,
                "type":      n.node_type,
                "color":     NODE_TYPES.get(n.node_type, {}).get("color","#888"),
                "size":      NODE_TYPES.get(n.node_type, {}).get("size", 12),
                "owned":     n.is_owned,
                "target":    n.is_target,
                "risk":      n.risk_score,
                "ip":        n.ip,
                "hostname":  n.hostname,
            }
            for n in self.nodes
        ]
        edges_json = [
            {
                "source":      e.src,
                "target":      e.dst,
                "type":        e.edge_type,
                "technique":   e.technique,
                "weight":      e.weight,
                "color":       EDGE_TYPES.get(e.edge_type, {}).get("color","#555"),
                "description": e.description,
            }
            for e in self.edges_
        ]
        paths_json = [
            {"id": p.path_id, "nodes": p.nodes,
             "feasibility": p.feasibility, "weight": p.total_weight}
            for p in (paths or [])
        ]

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>NEXUS SPECTER PRO — Attack Graph</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
  body {{ background:#0A0A0A; color:#E8E8E8; font-family:'JetBrains Mono',monospace;
         margin:0; overflow:hidden; }}
  .header {{ background:#0D0D0D; border-bottom:2px solid #7B00FF;
             padding:12px 24px; display:flex; justify-content:space-between;
             align-items:center; }}
  .header h1 {{ color:#7B00FF; font-size:16px; letter-spacing:4px; margin:0; }}
  .header .sub {{ color:#00FFD4; font-size:11px; }}
  #graph {{ width:100vw; height:calc(100vh - 52px); }}
  .node-label {{ fill:#E8E8E8; font-size:10px; font-family:monospace;
                 pointer-events:none; }}
  .tooltip {{ position:absolute; background:#111; border:1px solid #7B00FF;
              border-radius:6px; padding:10px 14px; font-size:11px;
              pointer-events:none; color:#E8E8E8; max-width:250px; }}
  .legend {{ position:fixed; bottom:20px; left:20px; background:#0D0D0D;
             border:1px solid #1E1E1E; border-radius:8px; padding:14px;
             font-size:10px; }}
  .legend-item {{ display:flex; align-items:center; gap:8px; margin:4px 0; }}
  .legend-dot {{ width:10px; height:10px; border-radius:50%; }}
  .stats {{ position:fixed; top:62px; right:20px; background:#0D0D0D;
            border:1px solid #1E1E1E; border-radius:8px; padding:14px; font-size:11px; }}
  .stat {{ color:#00FFD4; margin:3px 0; }}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ NEXUS SPECTER PRO — ATTACK GRAPH</h1>
  <div class="sub">OPTIMIUM NEXUS LLC | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
</div>

<div class="stats">
  <div class="stat">Nodes: {len(nodes_json)}</div>
  <div class="stat">Edges: {len(edges_json)}</div>
  <div class="stat">Paths: {len(paths_json)}</div>
</div>

<div class="legend">
  {''.join(f'<div class="legend-item"><div class="legend-dot" style="background:{v["color"]}"></div>{k}</div>' for k,v in list(NODE_TYPES.items())[:8])}
</div>

<div id="tooltip" class="tooltip" style="display:none"></div>
<svg id="graph"></svg>

<script>
const graphData = {{
  nodes: {json.dumps(nodes_json)},
  links: {json.dumps(edges_json)},
  paths: {json.dumps(paths_json)},
}};

const svg    = d3.select("#graph");
const width  = window.innerWidth;
const height = window.innerHeight - 52;
const tooltip= d3.select("#tooltip");

svg.attr("width", width).attr("height", height);

// Defs: arrowhead
const defs = svg.append("defs");
defs.append("marker")
  .attr("id","arrow").attr("viewBox","0 -5 10 10")
  .attr("refX",20).attr("refY",0)
  .attr("markerWidth",6).attr("markerHeight",6)
  .attr("orient","auto")
  .append("path").attr("d","M0,-5L10,0L0,5").attr("fill","#555");

const g = svg.append("g");

// Zoom
svg.call(d3.zoom().on("zoom", e => g.attr("transform", e.transform)));

// Force simulation
const simulation = d3.forceSimulation(graphData.nodes)
  .force("link",   d3.forceLink(graphData.links).id(d=>d.id).distance(100).strength(0.5))
  .force("charge", d3.forceManyBody().strength(-300))
  .force("center", d3.forceCenter(width/2, height/2))
  .force("collision", d3.forceCollide(30));

// Links
const link = g.append("g").selectAll("line")
  .data(graphData.links).join("line")
  .attr("stroke",       d => d.color || "#555")
  .attr("stroke-width", d => Math.max(1, 3 - d.weight/3))
  .attr("stroke-dasharray", d => d.type === "network_reach" ? "4,4" : null)
  .attr("marker-end",   "url(#arrow)")
  .attr("opacity", 0.7);

// Nodes
const node = g.append("g").selectAll("circle")
  .data(graphData.nodes).join("circle")
  .attr("r",    d => d.size || 12)
  .attr("fill", d => d.color || "#7B00FF")
  .attr("stroke", d => d.owned ? "#FF003C" : (d.target ? "#FFD700" : "#333"))
  .attr("stroke-width", d => (d.owned || d.target) ? 3 : 1)
  .style("cursor","pointer")
  .call(d3.drag()
    .on("start", (e,d) => {{ if(!e.active) simulation.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
    .on("drag",  (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
    .on("end",   (e,d) => {{ if(!e.active) simulation.alphaTarget(0); d.fx=null; d.fy=null; }})
  )
  .on("mouseover", (e,d) => {{
    tooltip.style("display","block")
      .style("left", (e.pageX+15)+"px").style("top", (e.pageY-10)+"px")
      .html(`<strong style="color:#7B00FF">${{d.label}}</strong><br>
             Type: ${{d.type}}<br>Risk: ${{d.risk||0}}/100<br>
             ${{d.ip ? "IP: "+d.ip+"<br>" : ""}}
             ${{d.owned ? "<span style='color:#FF003C'>OWNED</span>" : ""}}
             ${{d.target ? "<span style='color:#FFD700'>HIGH-VALUE TARGET</span>" : ""}}`);
  }})
  .on("mouseout", () => tooltip.style("display","none"));

// Labels
const label = g.append("g").selectAll("text")
  .data(graphData.nodes).join("text")
  .attr("class","node-label")
  .attr("dx",14).attr("dy",4)
  .text(d => d.label.length > 18 ? d.label.slice(0,16)+"…" : d.label);

// Tick
simulation.on("tick", () => {{
  link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
      .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
  node.attr("cx",d=>d.x).attr("cy",d=>d.y);
  label.attr("x",d=>d.x).attr("y",d=>d.y);
}});
</script>
</body>
</html>"""

        out_path = self.output_dir / filename
        out_path.write_text(html, encoding="utf-8")
        console.print(f"[bold #00FFD4]  ✅ D3 attack graph: {out_path}[/bold #00FFD4]")
        return out_path

    def export_networkx_json(self) -> Path:
        """Export raw NetworkX graph as node-link JSON."""
        if not NX_OK or self.G is None:
            return None
        data = nx.node_link_data(self.G)
        out  = self.output_dir / "attack_graph.json"
        out.write_text(json.dumps(data, indent=2, default=str))
        return out

    def run(self, session_data: dict = None) -> dict:
        console.print("[bold #7B00FF]  🕸️  Attack Graph Engine starting...[/bold #7B00FF]")

        if session_data:
            self.build_from_mission_data(session_data)
        elif not self.nodes:
            # Demo: minimal example graph
            self._build_demo_graph()

        paths      = self.find_attack_paths()
        chokepoints= self.find_chokepoints()

        self._print_paths(paths)

        # Blast radius for attacker node
        br = self.blast_radius("ATTACKER") if NX_OK else {}

        # Exports
        html_path = self.export_d3_html(paths)
        json_path = self.export_networkx_json()

        console.print(f"[bold #00FFD4]  ✅ Attack graph complete — "
                       f"{len(paths)} paths | {len(chokepoints)} chokepoints[/bold #00FFD4]")
        console.print(f"  [#7B00FF]→ Visualisation: {html_path}[/#7B00FF]")

        return {
            "nodes_count":   len(self.nodes),
            "edges_count":   len(self.edges_),
            "attack_paths":  [p.__dict__ for p in paths],
            "chokepoints":   chokepoints,
            "blast_radius":  br,
            "html_export":   str(html_path),
            "json_export":   str(json_path) if json_path else "",
        }

    def _build_demo_graph(self):
        """Build a minimal demo graph when no session data provided."""
        nodes = [
            AttackNode("ATTACKER",  "Attacker",        "attacker",   is_owned=True),
            AttackNode("WEB01",     "web01.corp.local", "host",       ip="10.0.1.10", risk_score=60),
            AttackNode("VULN01",    "CVE-2021-44228",  "vulnerability", risk_score=90),
            AttackNode("DB01",      "db01.corp.local",  "database",   ip="10.0.2.10", risk_score=80),
            AttackNode("DC01",      "DC01.corp.local",  "domain_controller", is_target=True, risk_score=95),
            AttackNode("DA",        "Domain Admin",     "domain_admin",     is_target=True, risk_score=100),
        ]
        edges = [
            AttackEdge("ATTACKER","WEB01",  "network_reach",  "T1190", 1),
            AttackEdge("WEB01",  "VULN01",  "exploits",       "T1190", 1),
            AttackEdge("VULN01", "DB01",    "lateral_move",   "T1021", 3),
            AttackEdge("VULN01", "DC01",    "lateral_move",   "T1021", 4),
            AttackEdge("DB01",   "DC01",    "lateral_move",   "T1550", 2),
            AttackEdge("DC01",   "DA",      "escalates_to",   "T1003", 2),
        ]
        for n in nodes: self.add_node(n)
        for e in edges: self.add_edge(e)
