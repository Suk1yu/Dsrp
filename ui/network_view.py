"""
ui/network_view.py

Stage 2 Network Analysis View — Textual TUI panel.
Layout:
  ┌──────────────────┬──────────────────┐
  │ Active Conns     │ Tracker Alerts   │
  ├──────────────────┼──────────────────┤
  │ Top Domains      │ WiFi Devices     │
  └──────────────────┴──────────────────┘

ASCII connection tree displayed below.
CPU cost: Refresh every 5s — minimal.
"""

import time
import threading
from pathlib import Path
from typing import Optional

try:
    from textual.app import App, ComposeResult
    from textual.widgets import (
        Header, Footer, Static, DataTable,
        Label, Button, Log
    )
    from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
    from textual.reactive import reactive
    from textual import events
    TEXTUAL_OK = True
except ImportError:
    TEXTUAL_OK = False

from network.connection_tracker import ConnectionTracker
from network.dns_monitor import DNSMonitor
from network.network_mapper import NetworkMapper
from network.tracker_detector import TrackerDetector


# ---------------------------------------------------------------------------
# Rich-only fallback view (when Textual not installed)
# ---------------------------------------------------------------------------

def run_network_view_cli():
    """Fallback: rich-powered live CLI network view."""
    import time
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.live import Live
    from rich.layout import Layout

    console = Console()

    # Init modules
    tracker_db_path = Path(__file__).parent.parent / "data" / "tracker_domains.json"
    detector = TrackerDetector(str(tracker_db_path) if tracker_db_path.exists() else None)
    tracker_db = detector.build_flat_dict()

    conn_tracker = ConnectionTracker(poll_interval=5.0, tracker_db=tracker_db)
    dns_monitor  = DNSMonitor(poll_interval=3.0, tracker_db=tracker_db)
    net_mapper   = NetworkMapper(scan_interval=120.0)

    conn_tracker.start()
    dns_monitor.start()
    net_mapper.start_periodic()

    console.print("[bold cyan]DSRP Stage 2 — Network Analysis View[/bold cyan]")
    console.print("[dim]Press Ctrl+C to exit | WiFi scan every 120s[/dim]\n")

    def make_layout():
        layout = Layout()
        layout.split_column(
            Layout(name="top", ratio=3),
            Layout(name="bottom", ratio=2),
        )
        layout["top"].split_row(
            Layout(name="connections"),
            Layout(name="trackers"),
        )
        layout["bottom"].split_row(
            Layout(name="domains"),
            Layout(name="devices"),
        )
        return layout

    def build_connections_panel():
        table = Table(title="Active Connections", show_lines=False,
                      title_style="bold cyan", expand=True)
        table.add_column("Process", style="cyan", width=16)
        table.add_column("Remote", width=22)
        table.add_column("Port", width=6)
        table.add_column("⚠", width=2)

        conns = conn_tracker.get_active_connections()
        for c in conns[:15]:
            host = (c.remote_hostname or c.remote_ip)[:22]
            flag = "⚠" if c.is_suspicious else ""
            table.add_row(
                c.process_name[:16],
                host,
                str(c.remote_port),
                flag,
            )
        if not conns:
            table.add_row("[dim]polling...[/dim]", "", "", "")
        return Panel(table, border_style="blue")

    def build_tracker_panel():
        table = Table(title="Tracker Alerts", show_lines=False,
                      title_style="bold red", expand=True)
        table.add_column("Domain", style="yellow", no_wrap=True)
        table.add_column("Tracker", style="red")
        table.add_column("Count", width=6)

        stats = dns_monitor.get_tracker_alerts(limit=12)
        for s in stats:
            table.add_row(s.domain[:28], s.tracker_name[:22], str(s.request_count))

        # Also add tracker connections
        tracker_conns = conn_tracker.get_tracker_connections()
        for c in tracker_conns[:5]:
            table.add_row(
                c.remote_hostname[:28] or c.remote_ip,
                c.tracker_name[:22],
                "conn"
            )

        if not stats and not tracker_conns:
            table.add_row("[dim]no trackers detected[/dim]", "", "")
        return Panel(table, border_style="red")

    def build_domains_panel():
        table = Table(title="Top Domains (DNS)", show_lines=False,
                      title_style="bold yellow", expand=True)
        table.add_column("Domain", style="cyan", no_wrap=True)
        table.add_column("Requests", width=9)
        table.add_column("Type", width=10)

        domain_stats = dns_monitor.get_domain_stats(top=15)
        for s in domain_stats:
            dtype = "[red]TRACKER[/red]" if s.is_tracker else "[green]ok[/green]"
            table.add_row(s.domain[:30], str(s.request_count), dtype)

        if not domain_stats:
            table.add_row("[dim]no DNS activity yet[/dim]", "", "")
        return Panel(table, border_style="yellow")

    def build_devices_panel():
        table = Table(title="WiFi Devices", show_lines=False,
                      title_style="bold green", expand=True)
        table.add_column("IP", style="cyan", width=16)
        table.add_column("Name / Vendor", width=22)
        table.add_column("MAC", style="dim", width=18)

        devices = net_mapper.get_devices()
        for dev in devices[:12]:
            table.add_row(
                dev.ip,
                dev.display_name[:22],
                dev.mac or "—",
            )

        if not devices:
            scan_status = "scanning..." if net_mapper.is_scanning() else "waiting for scan"
            table.add_row(f"[dim]{scan_status}[/dim]", "", "")
        return Panel(table, border_style="green")

    layout = make_layout()

    try:
        with Live(layout, refresh_per_second=0.5, screen=True):
            while True:
                layout["connections"].update(build_connections_panel())
                layout["trackers"].update(build_tracker_panel())
                layout["domains"].update(build_domains_panel())
                layout["devices"].update(build_devices_panel())
                time.sleep(5)
    except KeyboardInterrupt:
        conn_tracker.stop()
        dns_monitor.stop()
        net_mapper.stop()
        console.print("\n[yellow]Network view stopped.[/yellow]")


# ---------------------------------------------------------------------------
# ASCII tree view (lightweight alternative)
# ---------------------------------------------------------------------------

def print_ascii_network_snapshot():
    """Print a one-shot ASCII tree of current connections."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    tracker_db_path = Path(__file__).parent.parent / "data" / "tracker_domains.json"
    detector = TrackerDetector(str(tracker_db_path) if tracker_db_path.exists() else None)
    tracker_db = detector.build_flat_dict()

    ct = ConnectionTracker(poll_interval=5.0, tracker_db=tracker_db)
    ct.start()
    console.print("[dim]Collecting connection data…[/dim]")
    time.sleep(6)

    ascii_tree = ct.get_ascii_tree(max_apps=20)
    console.print(Panel(ascii_tree, title="Connection Map", border_style="cyan"))

    stats = ct.get_stats()
    console.print(
        f"\n[dim]Apps: {stats['active_apps']}  "
        f"Connections: {stats['active_connections']}  "
        f"Trackers: {stats['tracker_connections']}[/dim]"
    )
    ct.stop()


# ---------------------------------------------------------------------------
# Textual Widget (for embedding in full dashboard)
# ---------------------------------------------------------------------------

if TEXTUAL_OK:
    from textual.widgets import Static
    from textual.reactive import reactive

    class NetworkSummaryWidget(Static):
        """
        Embeddable Textual widget showing network summary.
        Refreshes every 5 seconds via set_interval.
        """

        def __init__(self, conn_tracker: ConnectionTracker,
                     dns_monitor: DNSMonitor,
                     net_mapper: NetworkMapper,
                     **kwargs):
            super().__init__(**kwargs)
            self._ct = conn_tracker
            self._dns = dns_monitor
            self._nm = net_mapper

        def on_mount(self):
            self.set_interval(5, self.refresh_data)

        def refresh_data(self):
            self.update(self._build_text())

        def _build_text(self) -> str:
            lines = []

            # --- Active connections summary ---
            conns = self._ct.get_active_connections()
            tracker_conns = self._ct.get_tracker_connections()
            lines.append(f"[bold cyan]Active Connections:[/bold cyan] {len(conns)}  "
                         f"[red]Trackers:[/red] {len(tracker_conns)}")
            lines.append("")

            # Top 8 connections
            for c in conns[:8]:
                host = (c.remote_hostname or c.remote_ip)[:25]
                flag = " [red]⚠[/red]" if c.is_suspicious or c.is_tracker else ""
                lines.append(f"  [cyan]{c.process_name[:14]:<14}[/cyan] → {host}:{c.remote_port}{flag}")

            lines.append("")

            # --- Top domains ---
            lines.append("[bold yellow]Top DNS Domains:[/bold yellow]")
            for s in self._dns.get_domain_stats(top=6):
                tag = " [red]⚠[/red]" if s.is_tracker else ""
                lines.append(f"  {s.domain[:28]:<28} {s.request_count:>4}{tag}")

            lines.append("")

            # --- WiFi devices ---
            devices = self._nm.get_devices()
            lines.append(f"[bold green]WiFi Devices:[/bold green] {len(devices)}")
            for dev in devices[:6]:
                lines.append(f"  [cyan]{dev.ip:<16}[/cyan] {dev.display_name[:22]}")

            return "\n".join(lines)