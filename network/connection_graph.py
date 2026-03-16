"""
network/connection_graph.py
Builds a network connection graph using NetworkX.
Nodes: apps, domains, devices. Edges: connections.
Renders using matplotlib.
"""

import os
import json
from typing import Optional

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend for Termux
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MPL_AVAILABLE = True
except ImportError:
    MPL_AVAILABLE = False


NODE_COLORS = {
    "app": "#4CAF50",
    "domain": "#2196F3",
    "device": "#FF9800",
    "ip": "#F44336",
    "unknown": "#9E9E9E",
}

NODE_SHAPES = {
    "app": "s",       # square
    "domain": "o",    # circle
    "device": "D",    # diamond
    "ip": "^",        # triangle
}


class ConnectionGraph:
    """
    Maintains a directed multigraph of network relationships.
    Can be built from packet records, app profiles, and nmap scan results.
    """

    def __init__(self):
        if NX_AVAILABLE:
            self.graph = nx.DiGraph()
        else:
            self.graph = None
        self._node_types: dict[str, str] = {}
        self._edge_weights: dict[tuple, int] = {}

    def add_node(self, node_id: str, node_type: str = "unknown",
                 label: str = "", **attrs):
        if not NX_AVAILABLE:
            return
        self._node_types[node_id] = node_type
        self.graph.add_node(node_id, node_type=node_type,
                            label=label or node_id, **attrs)

    def add_edge(self, src: str, dst: str, edge_type: str = "connection",
                 weight: int = 1, **attrs):
        if not NX_AVAILABLE:
            return
        key = (src, dst)
        self._edge_weights[key] = self._edge_weights.get(key, 0) + weight
        if self.graph.has_edge(src, dst):
            self.graph[src][dst]["weight"] = self._edge_weights[key]
        else:
            self.graph.add_edge(src, dst, edge_type=edge_type,
                                weight=weight, **attrs)

    def add_from_packets(self, packets: list):
        """Build graph edges from PacketRecord list."""
        for pkt in packets:
            src = getattr(pkt, "src_ip", "")
            dst = getattr(pkt, "dst_ip", "")
            dns = getattr(pkt, "dns_query", "")

            if not src or not dst:
                continue

            if src not in self.graph.nodes:
                self.add_node(src, "ip")
            if dst not in self.graph.nodes:
                self.add_node(dst, "ip")

            self.add_edge(src, dst, "packet")

            if dns:
                domain_id = f"dns:{dns}"
                if domain_id not in self.graph.nodes:
                    self.add_node(domain_id, "domain", label=dns)
                self.add_edge(src, domain_id, "dns_query")

    def add_from_app_profiles(self, profiles: list):
        """Add app nodes from AppProfile list."""
        for profile in profiles:
            pkg = profile.package_name
            if pkg not in self.graph.nodes:
                self.add_node(pkg, "app", label=pkg.split(".")[-1])

    def add_from_devices(self, devices: list):
        """Add device nodes from NetworkDevice list."""
        for dev in devices:
            node_id = f"device:{dev.ip}"
            if node_id not in self.graph.nodes:
                self.add_node(node_id, "device",
                              label=dev.hostname or dev.ip,
                              mac=dev.mac, vendor=dev.vendor)

    def get_stats(self) -> dict:
        if not NX_AVAILABLE or not self.graph:
            return {}
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": round(nx.density(self.graph), 4) if self.graph.number_of_nodes() > 1 else 0,
            "components": nx.number_weakly_connected_components(self.graph),
        }

    def get_top_nodes_by_degree(self, n: int = 10) -> list[tuple]:
        if not NX_AVAILABLE or not self.graph:
            return []
        degrees = dict(self.graph.degree())
        return sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:n]

    def render(self, output_path: str = "/tmp/dsrp_network.png",
               figsize: tuple = (16, 12)) -> Optional[str]:
        """Render graph to PNG file."""
        if not NX_AVAILABLE or not MPL_AVAILABLE:
            return None
        if self.graph.number_of_nodes() == 0:
            return None

        fig, ax = plt.subplots(1, 1, figsize=figsize)
        fig.patch.set_facecolor("#1a1a2e")
        ax.set_facecolor("#16213e")

        # Layout
        if self.graph.number_of_nodes() <= 50:
            pos = nx.spring_layout(self.graph, k=2.0, iterations=50, seed=42)
        else:
            pos = nx.kamada_kawai_layout(self.graph)

        # Separate nodes by type
        type_groups: dict[str, list] = {}
        for node in self.graph.nodes():
            t = self._node_types.get(node, "unknown")
            type_groups.setdefault(t, []).append(node)

        # Draw nodes by type
        for node_type, nodes in type_groups.items():
            color = NODE_COLORS.get(node_type, "#9E9E9E")
            nx.draw_networkx_nodes(
                self.graph, pos, nodelist=nodes, ax=ax,
                node_color=color, node_size=400, alpha=0.9,
            )

        # Edge weights
        weights = [self.graph[u][v].get("weight", 1) for u, v in self.graph.edges()]
        max_w = max(weights) if weights else 1
        widths = [1 + 3 * (w / max_w) for w in weights]

        nx.draw_networkx_edges(
            self.graph, pos, ax=ax,
            edge_color="#546e7a", arrows=True,
            arrowsize=12, width=widths, alpha=0.6,
        )

        # Labels for small graphs
        if self.graph.number_of_nodes() <= 60:
            labels = {n: self.graph.nodes[n].get("label", n)[:15]
                      for n in self.graph.nodes()}
            nx.draw_networkx_labels(
                self.graph, pos, labels=labels, ax=ax,
                font_size=7, font_color="#ecf0f1",
            )

        # Legend
        legend_patches = [
            mpatches.Patch(color=color, label=ntype.capitalize())
            for ntype, color in NODE_COLORS.items()
            if ntype in type_groups
        ]
        ax.legend(handles=legend_patches, loc="upper left",
                  facecolor="#1a1a2e", labelcolor="white", fontsize=9)

        stats = self.get_stats()
        ax.set_title(
            f"DSRP Network Connection Graph  |  "
            f"Nodes: {stats.get('nodes', 0)}  "
            f"Edges: {stats.get('edges', 0)}",
            color="white", fontsize=12, pad=15,
        )
        ax.axis("off")

        plt.tight_layout()
        plt.savefig(output_path, dpi=120, bbox_inches="tight",
                    facecolor=fig.get_facecolor())
        plt.close(fig)
        return output_path

    def export_gexf(self, path: str):
        """Export graph to GEXF format for Gephi."""
        if NX_AVAILABLE and self.graph:
            nx.write_gexf(self.graph, path)

    def export_json(self, path: str):
        """Export graph as node-link JSON."""
        if NX_AVAILABLE and self.graph:
            data = nx.node_link_data(self.graph)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)