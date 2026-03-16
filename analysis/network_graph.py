"""
analysis/network_graph.py

On-demand network connection graph.
Builds a directed graph from live connection data and renders it to PNG.

Design rules (Stage 4 lightweight):
  - max 50 nodes (pruned by degree)
  - only built when user requests it (not continuous)
  - renders to file — does not keep a live figure in memory
  - ASCII tree always available as zero-cost fallback

Node types: device / app / domain / ip
Edge types: connection / dns / tracker
"""

import time
import math
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import networkx as nx
    NX_OK = True
except ImportError:
    NX_OK = False

try:
    import matplotlib
    matplotlib.use("Agg")          # headless — no display needed
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MPL_OK = True
except ImportError:
    MPL_OK = False


MAX_NODES = 50                    # hard cap to keep rendering fast
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "graphs"

NODE_COLOR = {
    "device":  "#00BCD4",
    "app":     "#4CAF50",
    "domain":  "#FF9800",
    "ip":      "#F44336",
    "tracker": "#E91E63",
}

EDGE_COLOR = {
    "connection": "#546E7A",
    "dns":        "#1565C0",
    "tracker":    "#E91E63",
}


# ---------------------------------------------------------------------------
# Graph node/edge
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    node_id: str
    node_type: str          # device / app / domain / ip / tracker
    label: str = ""
    weight: int = 1         # degree / connection count
    is_tracker: bool = False
    is_malicious: bool = False
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    src: str
    dst: str
    edge_type: str = "connection"
    weight: int = 1
    is_tracker: bool = False


# ---------------------------------------------------------------------------
# NetworkGraph
# ---------------------------------------------------------------------------

class NetworkGraph:
    """
    On-demand network connection graph.
    Build once from data sources, then render or query.
    """

    def __init__(self):
        if NX_OK:
            self._g = nx.DiGraph()
        else:
            self._g = None
        self._nodes: dict[str, GraphNode] = {}
        self._edge_counts: Counter = Counter()

    # ------------------------------------------------------------------
    # Construction API
    # ------------------------------------------------------------------

    def add_node(self, node_id: str, node_type: str,
                 label: str = "", **meta) -> GraphNode:
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            label=label or node_id,
            metadata=meta,
        )
        self._nodes[node_id] = node
        if NX_OK:
            self._g.add_node(node_id, **vars(node))
        return node

    def add_edge(self, src: str, dst: str,
                 edge_type: str = "connection",
                 is_tracker: bool = False):
        if src not in self._nodes:
            self.add_node(src, "ip", src)
        if dst not in self._nodes:
            self.add_node(dst, "domain" if "." in dst else "ip", dst)

        key = (src, dst)
        self._edge_counts[key] += 1
        w = self._edge_counts[key]

        edge = GraphEdge(src=src, dst=dst, edge_type=edge_type,
                         weight=w, is_tracker=is_tracker)
        if NX_OK:
            if self._g.has_edge(src, dst):
                self._g[src][dst]["weight"] = w
            else:
                self._g.add_edge(src, dst, weight=1,
                                 edge_type=edge_type, is_tracker=is_tracker)

        # Update node degrees
        if src in self._nodes:
            self._nodes[src].weight += 1
        if dst in self._nodes:
            self._nodes[dst].weight += 1

    # ------------------------------------------------------------------
    # Import from live data
    # ------------------------------------------------------------------

    def build_from_connections(self,
                                connections: list,
                                tracker_db: dict = None,
                                device_label: str = "Android Device"):
        """
        Build graph from a list of ConnectionMeta objects.
        connections: from PacketMetadataCollector or ConnectionTracker
        tracker_db: {domain: tracker_name}
        """
        self.clear()
        tracker_db = tracker_db or {}

        # Root device node
        device_id = "device:local"
        self.add_node(device_id, "device", device_label)

        # Group by app
        app_to_remotes: dict[str, list] = defaultdict(list)
        for conn in connections:
            app = getattr(conn, "process_name", "") or "unknown"
            remote_host = getattr(conn, "remote_hostname", "") or \
                          getattr(conn, "remote_ip", "")
            remote_port = getattr(conn, "remote_port", 0)
            is_tracker_conn = getattr(conn, "is_tracker", False)
            if remote_host:
                app_to_remotes[app].append((remote_host, remote_port,
                                            is_tracker_conn))

        # Prune to top apps by connection count
        top_apps = sorted(app_to_remotes.items(),
                          key=lambda x: len(x[1]), reverse=True)[:20]

        for app, remotes in top_apps:
            app_id = f"app:{app}"
            if app_id not in self._nodes:
                self.add_node(app_id, "app", app[:20])
            self.add_edge(device_id, app_id, "connection")

            # Top 5 remotes per app (keep graph manageable)
            for host, port, is_t in remotes[:5]:
                domain_id = f"domain:{host}"
                is_t = is_t or bool(tracker_db.get(
                    host.lower().strip("."), ""))
                ntype = "tracker" if is_t else "domain"

                if domain_id not in self._nodes:
                    self.add_node(domain_id, ntype,
                                  host[:30], is_tracker=is_t)
                self.add_edge(app_id, domain_id,
                              "tracker" if is_t else "connection",
                              is_tracker=is_t)

        self._prune_to_max(MAX_NODES)

    def build_from_dns_stats(self, domain_stats: list,
                              tracker_db: dict = None):
        """Build from DNS monitor domain stats."""
        self.clear()
        tracker_db = tracker_db or {}
        device_id = "device:local"
        self.add_node(device_id, "device", "Android Device")

        for stat in domain_stats[:MAX_NODES - 1]:
            domain = stat.domain
            is_t = stat.is_tracker or bool(tracker_db.get(domain, ""))
            ntype = "tracker" if is_t else "domain"
            d_id = f"domain:{domain}"
            if d_id not in self._nodes:
                self.add_node(d_id, ntype, domain[:30],
                              is_tracker=is_t)
            for _ in range(min(stat.request_count, 10)):
                self.add_edge(device_id, d_id,
                              "tracker" if is_t else "dns", is_t)

        self._prune_to_max(MAX_NODES)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        if not NX_OK or not self._g:
            return {"nodes": len(self._nodes)}
        n = self._g.number_of_nodes()
        e = self._g.number_of_edges()
        trackers = sum(1 for nd in self._nodes.values() if nd.is_tracker)
        return {
            "nodes": n,
            "edges": e,
            "tracker_nodes": trackers,
            "density": round(nx.density(self._g), 4) if n > 1 else 0,
            "weakly_connected": nx.number_weakly_connected_components(self._g)
                                 if n > 0 else 0,
        }

    def get_top_nodes(self, n: int = 10) -> list[tuple[str, int]]:
        """Return top nodes by in-degree (most connected destinations)."""
        if not NX_OK:
            top = sorted(self._nodes.items(),
                         key=lambda x: x[1].weight, reverse=True)
            return [(k, v.weight) for k, v in top[:n]]
        degrees = dict(self._g.in_degree())
        return sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_tracker_nodes(self) -> list[GraphNode]:
        return [n for n in self._nodes.values() if n.is_tracker]

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------

    def render_png(self, output_path: str = None,
                   figsize: tuple = (14, 10)) -> Optional[str]:
        """Render graph to PNG. Returns path or None if failed."""
        if not NX_OK or not MPL_OK:
            return None
        if not self._g or self._g.number_of_nodes() == 0:
            return None

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        if output_path is None:
            ts = int(time.time())
            output_path = str(OUTPUT_DIR / f"graph_{ts}.png")

        fig, ax = plt.subplots(figsize=figsize)
        fig.patch.set_facecolor("#0D1117")
        ax.set_facecolor("#0D1117")

        # Layout
        n = self._g.number_of_nodes()
        if n <= 20:
            pos = nx.spring_layout(self._g, k=2.5, seed=42)
        elif n <= 40:
            pos = nx.kamada_kawai_layout(self._g)
        else:
            pos = nx.shell_layout(self._g)

        # Group nodes by type for separate draw calls
        by_type: dict[str, list] = defaultdict(list)
        for node in self._g.nodes():
            ntype = self._nodes.get(node, GraphNode(node, "ip")).node_type
            by_type[ntype].append(node)

        # Draw nodes
        for ntype, nodes in by_type.items():
            color = NODE_COLOR.get(ntype, "#9E9E9E")
            size  = 600 if ntype == "device" else (400 if ntype == "app" else 250)
            nx.draw_networkx_nodes(
                self._g, pos, nodelist=nodes, ax=ax,
                node_color=color, node_size=size, alpha=0.92,
            )

        # Draw edges by type
        for etype, ecolor in EDGE_COLOR.items():
            elist = [(u, v) for u, v, d in self._g.edges(data=True)
                     if d.get("edge_type") == etype]
            if elist:
                nx.draw_networkx_edges(
                    self._g, pos, edgelist=elist, ax=ax,
                    edge_color=ecolor, arrows=True,
                    arrowsize=10, width=1.2, alpha=0.55,
                )

        # Labels
        if n <= 35:
            labels = {nd: (self._nodes[nd].label[:14]
                           if nd in self._nodes else nd[:14])
                      for nd in self._g.nodes()}
            nx.draw_networkx_labels(
                self._g, pos, labels, ax=ax,
                font_size=6.5, font_color="#ECF0F1",
            )

        # Legend
        patches = [mpatches.Patch(color=c, label=t.capitalize())
                   for t, c in NODE_COLOR.items()
                   if t in by_type]
        ax.legend(handles=patches, loc="upper left",
                  facecolor="#161B22", labelcolor="white", fontsize=8)

        stats = self.get_stats()
        ax.set_title(
            f"DSRP Network Graph  │  "
            f"Nodes: {stats['nodes']}  Edges: {stats['edges']}  "
            f"Trackers: {stats['tracker_nodes']}",
            color="#ECF0F1", fontsize=11, pad=12,
        )
        ax.axis("off")
        plt.tight_layout(pad=0.5)
        plt.savefig(output_path, dpi=100, bbox_inches="tight",
                    facecolor=fig.get_facecolor())
        plt.close(fig)
        return output_path

    # ------------------------------------------------------------------
    # ASCII tree (zero-cost fallback)
    # ------------------------------------------------------------------

    def ascii_tree(self, max_depth: int = 2) -> str:
        """Always-available ASCII rendering — no matplotlib needed."""
        if not self._nodes:
            return "(empty graph — no data yet)"

        lines = []
        # Find root nodes (in-degree == 0 or device type)
        device_nodes = [n for n in self._nodes.values() if n.node_type == "device"]
        roots = device_nodes or list(self._nodes.values())[:1]

        for root in roots[:2]:
            lines.append(f"[{root.node_type.upper()}] {root.label}")
            if NX_OK and self._g:
                children = list(self._g.successors(root.node_id))
            else:
                children = [k for k, e in self._edge_counts.items()
                            if k[0] == root.node_id]
                children = [c[1] for c in children]

            children = children[:15]
            for i, child_id in enumerate(children):
                is_last = (i == len(children) - 1)
                prefix  = "└─" if is_last else "├─"
                node    = self._nodes.get(child_id)
                if node is None:
                    continue
                tracker_flag = " ⚠ TRACKER" if node.is_tracker else ""
                lines.append(f" {prefix} [{node.node_type[:3].upper()}] "
                             f"{node.label[:30]}{tracker_flag}")

                if max_depth >= 2 and NX_OK and self._g:
                    grandchildren = list(self._g.successors(child_id))[:5]
                    for j, gc_id in enumerate(grandchildren):
                        gc_node = self._nodes.get(gc_id)
                        if not gc_node:
                            continue
                        gc_last = (j == len(grandchildren) - 1)
                        gc_prefix = "   " + ("└─" if gc_last else "├─")
                        if is_last:
                            gc_prefix = "    " + ("└─" if gc_last else "├─")
                        t_flag = " ⚠" if gc_node.is_tracker else ""
                        lines.append(f" {gc_prefix} {gc_node.label[:28]}{t_flag}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def clear(self):
        self._nodes.clear()
        self._edge_counts.clear()
        if NX_OK:
            self._g.clear()

    def _prune_to_max(self, max_n: int):
        """Remove lowest-degree nodes until under max_n."""
        if not NX_OK or self._g.number_of_nodes() <= max_n:
            return
        # Always keep device and app nodes
        keep_types = {"device", "app"}
        removable = [
            (n, self._g.degree(n))
            for n in list(self._g.nodes())
            if self._nodes.get(n, GraphNode(n, "ip")).node_type not in keep_types
        ]
        removable.sort(key=lambda x: x[1])
        to_remove = len(self._g.nodes()) - max_n
        for node, _ in removable[:to_remove]:
            self._g.remove_node(node)
            self._nodes.pop(node, None)

    def export_gexf(self, path: str):
        if NX_OK and self._g:
            nx.write_gexf(self._g, path)