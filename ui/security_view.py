"""
ui/security_view.py

Stage 3 Security Dashboard — live alert console.
Shows: IDS alerts, AI anomalies, threat intel, malware behavior scores.

Two rendering modes:
  1. Rich live view (default — no Textual dependency)
  2. Textual widget (embedded in full dashboard)
"""

import time
import threading
from pathlib import Path
from collections import deque
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    RICH_OK = True
except ImportError:
    RICH_OK = False


SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

SEVERITY_BADGE = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🔵 LOW",
    "INFO":     "⚪ INFO",
}


# ---------------------------------------------------------------------------
# Rich live security view
# ---------------------------------------------------------------------------

def run_security_view(
        ids_engine=None,
        anomaly_detector=None,
        behavior_model=None,
        reputation_cache=None,
        refresh_secs: float = 3.0,
):
    """
    Full-screen rich live security console.
    Pass in pre-initialised Stage 3 module instances.
    """
    if not RICH_OK:
        print("Install rich: pip install rich")
        return

    console = Console()

    def build_layout():
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=1),
        )
        layout["main"].split_row(
            Layout(name="left",  ratio=2),
            Layout(name="right", ratio=1),
        )
        layout["left"].split_column(
            Layout(name="alerts",   ratio=2),
            Layout(name="anomaly",  ratio=1),
        )
        layout["right"].split_column(
            Layout(name="behavior", ratio=1),
            Layout(name="intel",    ratio=1),
        )
        return layout

    def header_panel():
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        ids_stats = ids_engine.get_stats() if ids_engine else {}
        total    = ids_stats.get("alerts_generated", 0)
        active   = ids_stats.get("active_alerts", 0)
        critical = ids_stats.get("by_severity", {}).get("CRITICAL", 0)
        high     = ids_stats.get("by_severity", {}).get("HIGH", 0)

        status_txt = (
            f"[bold cyan]DSRP Stage 3 — Security Console[/bold cyan]  "
            f"[dim]{now}[/dim]  │  "
            f"Alerts: [yellow]{total}[/yellow]  "
            f"Active: [yellow]{active}[/yellow]  "
            f"Critical: [red]{critical}[/red]  "
            f"High: [orange1]{high}[/orange1]"
        )
        return Panel(status_txt, style="blue", padding=(0, 1))

    def alerts_panel():
        table = Table(
            title="IDS Alerts",
            title_style="bold red",
            show_lines=False,
            expand=True,
            box=box.SIMPLE_HEAVY,
        )
        table.add_column("", width=2)
        table.add_column("Time", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Category", width=14)
        table.add_column("Description", no_wrap=False)
        table.add_column("×", width=4)

        if ids_engine:
            alerts = ids_engine.get_latest_alerts(n=20)
            for alert in reversed(alerts):
                style = SEVERITY_STYLE.get(alert.severity, "")
                ts    = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
                badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                         "LOW": "🔵", "INFO": "⚪"}.get(alert.severity, "⚪")
                acked = "[dim]✓[/dim]" if alert.acknowledged else ""
                table.add_row(
                    badge,
                    ts,
                    f"[{style}]{alert.severity}[/{style}]",
                    alert.category[:13],
                    alert.description[:65],
                    f"[dim]{alert.count if alert.count > 1 else ''}[/dim]",
                )
        else:
            table.add_row("", "", "[dim]IDS engine not connected[/dim]", "", "", "")

        return Panel(table, border_style="red")

    def anomaly_panel():
        table = Table(
            title="AI Anomaly Detection",
            title_style="bold yellow",
            show_lines=False,
            expand=True,
            box=box.SIMPLE,
        )
        table.add_column("Time", width=8)
        table.add_column("Severity", width=10)
        table.add_column("Description", no_wrap=False)

        status_line = ""
        if anomaly_detector:
            status = anomaly_detector.get_status()
            if not status["model_trained"]:
                warmup_left = status["warmup_remaining"]
                status_line = f"[dim]Warming up… {warmup_left} windows remaining[/dim]"
                table.add_row("", "", status_line)
            else:
                alerts = anomaly_detector.get_alerts(limit=8, min_severity="LOW")
                for a in reversed(alerts[-8:]):
                    style = SEVERITY_STYLE.get(a.severity, "")
                    ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
                    table.add_row(
                        ts,
                        f"[{style}]{a.severity}[/{style}]",
                        a.description[:60],
                    )
                if not alerts:
                    table.add_row("", "[green]CLEAN[/green]",
                                  "No anomalies detected in current window")
        else:
            table.add_row("", "", "[dim]Not connected[/dim]")

        return Panel(table, border_style="yellow")

    def behavior_panel():
        table = Table(
            title="App Behavior (ML)",
            title_style="bold magenta",
            show_lines=False,
            expand=True,
            box=box.SIMPLE,
        )
        table.add_column("App", no_wrap=True)
        table.add_column("Risk", width=10)
        table.add_column("Prob", width=6)

        if behavior_model and hasattr(behavior_model, "_last_predictions"):
            for pred in behavior_model._last_predictions[-8:]:
                style = {
                    "MALICIOUS":  "bold red",
                    "SUSPICIOUS": "yellow",
                    "BENIGN":     "green",
                }.get(pred.risk_label, "white")
                app_short = pred.package_name.split(".")[-1][:18]
                table.add_row(
                    app_short,
                    f"[{style}]{pred.risk_level}[/{style}]",
                    f"{pred.probability_malware:.0%}",
                )
        else:
            table.add_row("[dim]Run app scan[/dim]", "", "")

        return Panel(table, border_style="magenta")

    def intel_panel():
        table = Table(
            title="Threat Intel",
            title_style="bold cyan",
            show_lines=False,
            expand=True,
            box=box.SIMPLE,
        )
        table.add_column("IOC", no_wrap=True)
        table.add_column("Rep", width=12)
        table.add_column("Score", width=6)

        if reputation_cache:
            malicious  = reputation_cache.get_malicious(limit=5)
            suspicious = reputation_cache.get_suspicious(limit=5)
            for entry in malicious[:5]:
                table.add_row(
                    entry.ioc[:25],
                    "[bold red]MALICIOUS[/bold red]",
                    f"{entry.score:.2f}",
                )
            for entry in suspicious[:4]:
                table.add_row(
                    entry.ioc[:25],
                    "[yellow]SUSPICIOUS[/yellow]",
                    f"{entry.score:.2f}",
                )
            if not malicious and not suspicious:
                table.add_row("[dim]No threats cached[/dim]", "", "")
        else:
            table.add_row("[dim]Not connected[/dim]", "", "")

        return Panel(table, border_style="cyan")

    layout = build_layout()
    console.print("[bold cyan]DSRP Stage 3 — Security Console[/bold cyan]  "
                  "[dim]Ctrl+C to exit[/dim]")

    try:
        with Live(layout, refresh_per_second=1 / refresh_secs,
                  screen=True, console=console):
            while True:
                layout["header"].update(header_panel())
                layout["alerts"].update(alerts_panel())
                layout["anomaly"].update(anomaly_panel())
                layout["behavior"].update(behavior_panel())
                layout["intel"].update(intel_panel())
                time.sleep(refresh_secs)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# Compact alert log (for embedding in larger layout)
# ---------------------------------------------------------------------------

def print_alert_summary(ids_engine, limit: int = 20):
    """Print a compact one-shot alert summary table."""
    if not RICH_OK:
        return
    console = Console()
    alerts = ids_engine.get_latest_alerts(limit)

    if not alerts:
        console.print("[green]No IDS alerts.[/green]")
        return

    table = Table(title=f"IDS Alert Summary [{len(alerts)}]",
                  show_lines=True)
    table.add_column("ID",       width=5, style="dim")
    table.add_column("Time",     width=9)
    table.add_column("Severity", width=10)
    table.add_column("Rule",     width=10, style="dim")
    table.add_column("Category", width=14)
    table.add_column("Description")
    table.add_column("MITRE",    width=12, style="dim")

    for a in reversed(alerts):
        style = SEVERITY_STYLE.get(a.severity, "")
        ts    = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
        table.add_row(
            str(a.alert_id),
            ts,
            f"[{style}]{a.severity}[/{style}]",
            a.rule_id,
            a.category,
            a.description[:55],
            a.mitre[:12] if a.mitre else "—",
        )

    console.print(table)

    # Stats footer
    stats = ids_engine.get_stats()
    by_sev = stats.get("by_severity", {})
    console.print(
        f"\n[dim]Total: {stats['alerts_generated']}  "
        f"Critical: [red]{by_sev.get('CRITICAL', 0)}[/red]  "
        f"High: [orange1]{by_sev.get('HIGH', 0)}[/orange1]  "
        f"Medium: [yellow]{by_sev.get('MEDIUM', 0)}[/yellow][/dim]"
    )