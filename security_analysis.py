#!/usr/bin/env python3
"""
security_analysis.py — Stage 3 Standalone Runner
Device Security Research Platform

Usage:
  python security_analysis.py              # Full security console (live)
  python security_analysis.py --ids        # IDS only (connect to live traffic)
  python security_analysis.py --anomaly    # AI anomaly detector only
  python security_analysis.py --scan       # Scan installed apps for malware
  python security_analysis.py --intel <ioc>  # Threat intel lookup
  python security_analysis.py --rules      # Show loaded IDS rules
  python security_analysis.py --status     # Engine status snapshot

CPU target: 5–10% total on mid-range ARM (Android Termux)
"""

import argparse
import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


# ---------------------------------------------------------------------------
# Mode: Full security console
# ---------------------------------------------------------------------------

def cmd_console(args):
    """Full live security console — all Stage 3 modules running."""
    from rich.console import Console
    console = Console()
    console.print("\n[bold cyan]DSRP Stage 3 — Security Console[/bold cyan]")
    console.print("[dim]Starting all security modules...[/dim]\n")

    from security_engine import SecurityEngine
    from network.packet_metadata import PacketMetadataCollector
    from network.connection_tracker import ConnectionTracker
    from network.tracker_detector import TrackerDetector

    # Load tracker database
    db_path = Path(__file__).parent / "data" / "tracker_domains.json"
    detector = TrackerDetector(str(db_path) if db_path.exists() else None)
    tracker_db = detector.build_flat_dict()

    # Start security engine
    engine = SecurityEngine(analysis_interval=15.0, enable_remote_intel=False)
    engine.start()

    # Start network metadata collector
    meta_collector = PacketMetadataCollector(poll_interval=5.0)

    def on_connections(conns):
        for conn in conns:
            engine.ingest_connection(conn)

    meta_collector.add_callback(on_connections)
    meta_collector.start()

    console.print("[green]All modules running.[/green] Warming up AI model...\n")

    from ui.security_view import run_security_view
    try:
        run_security_view(
            ids_engine=engine.ids,
            anomaly_detector=engine.anomaly,
            behavior_model=engine.behavior,
            reputation_cache=engine.reputation,
            refresh_secs=3.0,
        )
    finally:
        engine.stop()
        meta_collector.stop()


# ---------------------------------------------------------------------------
# Mode: IDS only
# ---------------------------------------------------------------------------

def cmd_ids(args):
    """Run IDS against live network connections. Prints alerts in real-time."""
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    console = Console()

    from ids.ids_engine import IDSEngine
    from network.packet_metadata import PacketMetadataCollector

    ids = IDSEngine(log_to_file=True)
    alert_log = []

    def on_alert(alert):
        alert_log.insert(0, alert)

    ids.add_callback(on_alert)

    meta = PacketMetadataCollector(poll_interval=3.0, resolve_hostnames=True)

    def on_conns(conns):
        for c in conns:
            ids.process_connection(c)

    meta.add_callback(on_conns)
    meta.start()

    console.print("\n[bold red]DSRP IDS — Live Rule Engine[/bold red]")
    console.print("[dim]Monitoring connections... Ctrl+C to stop[/dim]\n")

    def make_table():
        t = Table(title=f"IDS Alerts [{ids.get_stats()['alerts_generated']}]",
                  show_lines=False, expand=True)
        t.add_column("", width=2)
        t.add_column("Time", width=9)
        t.add_column("Severity", width=10)
        t.add_column("Rule", width=10, style="dim")
        t.add_column("Description", no_wrap=False)
        for a in alert_log[:25]:
            from ui.security_view import SEVERITY_STYLE
            style = SEVERITY_STYLE.get(a.severity, "")
            ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
            badge = {"CRITICAL": "🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(a.severity,"⚪")
            t.add_row(badge, ts, f"[{style}]{a.severity}[/{style}]",
                      a.rule_id, a.description[:70])
        if not alert_log:
            t.add_row("", "", "[green]CLEAN[/green]", "", "No alerts yet — watching...")
        return t

    try:
        with Live(make_table(), refresh_per_second=0.5, screen=False) as live:
            while True:
                live.update(make_table())
                time.sleep(2)
    except KeyboardInterrupt:
        meta.stop()
        console.print(f"\n[yellow]Stopped. {ids.get_stats()['alerts_generated']} alerts generated.[/yellow]")

    from ui.security_view import print_alert_summary
    print_alert_summary(ids)


# ---------------------------------------------------------------------------
# Mode: AI anomaly detector
# ---------------------------------------------------------------------------

def cmd_anomaly(args):
    """Run AI traffic anomaly detector. Shows feature windows and alerts."""
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    console = Console()

    from network.traffic_features import TrafficFeatureWindow, FEATURE_NAMES
    from ai.traffic_anomaly import TrafficAnomalyDetector
    from network.packet_metadata import PacketMetadataCollector

    fw = TrafficFeatureWindow(window_secs=30.0)
    detector = TrafficAnomalyDetector(feature_window=fw, analysis_interval=15.0)
    detector.start()

    meta = PacketMetadataCollector(poll_interval=3.0)
    meta.add_callback(lambda conns: [fw.add_from_connection(c) for c in conns])
    meta.start()

    console.print("\n[bold yellow]DSRP AI Anomaly Detector[/bold yellow]")
    console.print("[dim]Building baseline... alerts appear after warm-up[/dim]\n")

    def make_display():
        t = Table(show_lines=False, expand=True)
        t.add_column("Feature", style="cyan", width=28)
        t.add_column("Current Value", width=16)

        vec = fw.extract()
        if vec:
            for name, val in zip(FEATURE_NAMES, vec):
                t.add_row(name, f"{val:.3f}")
        else:
            t.add_row("[dim]collecting data...[/dim]", "")

        status = detector.get_status()
        alerts = detector.get_alerts(limit=10, min_severity="LOW")

        return t, status, alerts

    try:
        with Live(refresh_per_second=0.2, screen=False) as live:
            while True:
                table, status, alerts = make_display()

                from rich.layout import Layout
                from rich.panel import Panel
                from rich.text import Text

                warmup = status["warmup_remaining"]
                trained = status["model_trained"]
                model_status = (
                    f"[green]Model trained ({status['baseline_size']} windows)[/green]"
                    if trained else
                    f"[yellow]Warm-up: {status['windows_collected']}/{detector.WARMUP_WINDOWS}[/yellow]"
                )

                alert_lines = "\n".join(a.summary_line() for a in reversed(alerts[-8:])) or \
                              "[green]No anomalies detected[/green]"

                from rich.columns import Columns
                live.update(
                    Columns([
                        Panel(table, title="Traffic Features", border_style="yellow"),
                        Panel(
                            f"{model_status}\n\n{alert_lines}",
                            title="Anomaly Alerts",
                            border_style="red",
                        ),
                    ])
                )
                time.sleep(3)
    except KeyboardInterrupt:
        detector.stop()
        meta.stop()
        console.print("\n[yellow]Stopped.[/yellow]")


# ---------------------------------------------------------------------------
# Mode: App malware scan
# ---------------------------------------------------------------------------

def cmd_scan(args):
    """Scan installed apps using malware behavior model."""
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()

    from core.app_analyzer import AppAnalyzer
    from ai.malware_behavior_model import MalwareBehaviorModel, AppBehaviorSnapshot

    console.print("\n[bold magenta]DSRP App Malware Scanner (Stage 3)[/bold magenta]\n")

    analyzer = AppAnalyzer()
    model = MalwareBehaviorModel(auto_train=True)

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  transient=True) as p:
        task = p.add_task("Loading app list...", total=None)
        packages = analyzer.get_installed_packages()
        p.update(task, description=f"Scanning {len(packages)} apps...")

    table = Table(title=f"App Behavior Scan [{len(packages[:40])} apps]",
                  show_lines=True)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Risk Level", width=10)
    table.add_column("Probability", width=11)
    table.add_column("Label", width=12)
    table.add_column("Top Reason")

    high_risk = []

    for pkg in packages[:40]:
        profile = analyzer.analyze_package(pkg)
        snap = AppBehaviorSnapshot.from_profile(profile)
        pred = model.predict(snap)

        level = pred.risk_level
        style = {"CRITICAL": "bold red", "HIGH": "red",
                 "MEDIUM": "yellow", "LOW": "green"}.get(level, "white")
        reason = pred.explanation[0][:50] if pred.explanation else "—"

        table.add_row(
            pkg,
            f"[{style}]{level}[/{style}]",
            f"{pred.probability_malware:.1%}",
            pred.risk_label,
            reason,
        )
        if level in ("CRITICAL", "HIGH"):
            high_risk.append(pred)

    console.print(table)

    if high_risk:
        console.print(f"\n[bold red]{len(high_risk)} HIGH/CRITICAL risk apps:[/bold red]")
        for pred in high_risk:
            console.print(f"\n  [red]{pred.package_name}[/red]")
            for reason in pred.explanation:
                console.print(f"    • {reason}")
    else:
        console.print("\n[green]No high-risk apps detected.[/green]")


# ---------------------------------------------------------------------------
# Mode: Threat intel lookup
# ---------------------------------------------------------------------------

def cmd_intel(args):
    """Perform a threat intelligence lookup for an IP or domain."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    from intel.reputation_cache import ReputationCache
    cache = ReputationCache(enable_remote=True)

    for ioc in args.intel:
        console.print(f"\n[dim]Looking up: {ioc}[/dim]")
        entry = cache.lookup_sync(ioc)
        rep_style = {
            "MALICIOUS":  "bold red",
            "SUSPICIOUS": "yellow",
            "CLEAN":      "green",
            "UNKNOWN":    "dim",
        }.get(entry.reputation, "white")

        console.print(Panel(
            f"[bold]IOC:[/bold]         {entry.ioc}\n"
            f"[bold]Type:[/bold]        {entry.ioc_type}\n"
            f"[bold]Reputation:[/bold]  [{rep_style}]{entry.reputation}[/{rep_style}]\n"
            f"[bold]Score:[/bold]       {entry.score:.3f}\n"
            f"[bold]Sources:[/bold]     {', '.join(entry.sources) or 'none'}\n"
            f"[bold]Tags:[/bold]        {', '.join(entry.tags) or 'none'}",
            title=f"Threat Intel — {ioc}",
            border_style=rep_style,
        ))


# ---------------------------------------------------------------------------
# Mode: Show IDS rules
# ---------------------------------------------------------------------------

def cmd_rules(args):
    from rich.console import Console
    from rich.table import Table
    from ids.ids_engine import IDSEngine
    console = Console()

    ids = IDSEngine()
    rules = ids.get_rule_list()

    table = Table(title=f"Loaded IDS Rules [{len(rules)}]", show_lines=True)
    table.add_column("ID",       style="dim", width=10)
    table.add_column("Name",     style="cyan")
    table.add_column("Severity", width=10)
    table.add_column("Category", width=14)
    table.add_column("Enabled",  width=8)

    for r in rules:
        sev_style = {
            "CRITICAL": "bold red", "HIGH": "red",
            "MEDIUM": "yellow", "LOW": "cyan"
        }.get(r["severity"], "white")
        table.add_row(
            r["id"],
            r["name"],
            f"[{sev_style}]{r['severity']}[/{sev_style}]",
            r["category"],
            "[green]Yes[/green]" if r["enabled"] else "[red]No[/red]",
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Mode: Status snapshot
# ---------------------------------------------------------------------------

def cmd_status(args):
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    from security_engine import SecurityEngine
    engine = SecurityEngine()
    engine.start()
    time.sleep(1)
    status = engine.get_status()
    engine.stop()

    console.print(Panel(
        f"[bold]IDS Rules:[/bold]          {status['ids']['rules_loaded']}\n"
        f"[bold]Behavior Model:[/bold]     {'ready' if status['behavior_model_ready'] else 'training...'}\n"
        f"[bold]Anomaly Model:[/bold]      {'trained' if status['anomaly']['model_trained'] else 'warming up'}\n"
        f"[bold]Reputation Cache:[/bold]   {status['reputation']['cached_entries']} entries\n"
        f"[bold]ML Available:[/bold]       {status['anomaly']['ml_available']}\n",
        title="DSRP Stage 3 — Status",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DSRP Stage 3 — AI Security & Intrusion Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_analysis.py              # Full security console
  python security_analysis.py --ids        # IDS live alert stream
  python security_analysis.py --anomaly    # AI anomaly detector
  python security_analysis.py --scan       # Malware behavior scan
  python security_analysis.py --intel 8.8.8.8 api.example.com
  python security_analysis.py --rules      # Show IDS rules
  python security_analysis.py --status     # Engine status
        """
    )
    parser.add_argument("--ids",     action="store_true", help="IDS live mode")
    parser.add_argument("--anomaly", action="store_true", help="AI anomaly detector")
    parser.add_argument("--scan",    action="store_true", help="App malware scan")
    parser.add_argument("--intel",   nargs="+", metavar="IOC",
                        help="Threat intel lookup for IPs/domains")
    parser.add_argument("--rules",   action="store_true", help="Show IDS rules")
    parser.add_argument("--status",  action="store_true", help="Engine status")

    args = parser.parse_args()

    if args.ids:
        cmd_ids(args)
    elif args.anomaly:
        cmd_anomaly(args)
    elif args.scan:
        cmd_scan(args)
    elif args.intel:
        cmd_intel(args)
    elif args.rules:
        cmd_rules(args)
    elif args.status:
        cmd_status(args)
    else:
        cmd_console(args)


if __name__ == "__main__":
    main()