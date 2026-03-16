#!/usr/bin/env python3
"""
lab_analysis.py — Stage 4 Security Lab Runner
Device Security Research Platform

Usage:
  python lab_analysis.py              # Full interactive Security Lab menu
  python lab_analysis.py --graph      # Network graph (ASCII)
  python lab_analysis.py --graph-png  # Network graph PNG
  python lab_analysis.py --analysis   # Connection analysis report
  python lab_analysis.py --patterns   # Traffic pattern heatmap
  python lab_analysis.py --intel      # Threat intel dashboard
  python lab_analysis.py --ioc        # IOC database status
  python lab_analysis.py --ioc-update # Force IOC feed update
  python lab_analysis.py --apk <file> # APK static intelligence
  python lab_analysis.py --trackers <file>  # APK tracker scan
  python lab_analysis.py --demo       # Demo mode (synthetic data)

CPU target: 3–8% (on-demand analysis, not continuous)
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


# ---------------------------------------------------------------------------
# Helpers to set up live modules
# ---------------------------------------------------------------------------

def _start_live_modules(duration: float = 6.0):
    """Start Stage 2 modules, collect data for `duration` seconds, return them."""
    from rich.console import Console
    console = Console()
    console.print(f"[dim]Collecting live data for {duration:.0f}s...[/dim]")

    from network.connection_tracker import ConnectionTracker
    from network.dns_monitor import DNSMonitor
    from network.packet_metadata import PacketMetadataCollector
    from network.tracker_detector import TrackerDetector

    db_path = Path(__file__).parent / "data" / "tracker_domains.json"
    det = TrackerDetector(str(db_path) if db_path.exists() else None)
    tracker_db = det.build_flat_dict()

    ct = ConnectionTracker(poll_interval=3.0, tracker_db=tracker_db)
    dns = DNSMonitor(poll_interval=2.0, tracker_db=tracker_db)
    meta = PacketMetadataCollector(poll_interval=3.0)

    ct.start()
    dns.start()
    meta.start()

    time.sleep(duration)
    return ct, dns, meta


def _stop_live_modules(*modules):
    for m in modules:
        try:
            m.stop()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_lab(args):
    """Full interactive Security Lab menu."""
    ct, dns, meta = _start_live_modules(5.0)
    try:
        from ui.lab_view import SecurityLab
        from intel.reputation_cache import ReputationCache
        from intel.ioc_updater import IOCUpdater
        from analysis.connection_analysis import ConnectionAnalyser
        from analysis.traffic_patterns import TrafficPatternAnalyser

        rep = ReputationCache(enable_remote=False)
        ioc = IOCUpdater()
        ca = ConnectionAnalyser(window_secs=300.0)
        tp = TrafficPatternAnalyser()

        lab = SecurityLab(
            conn_tracker=ct,
            dns_monitor=dns,
            reputation_cache=rep,
            ioc_updater=ioc,
            connection_analyser=ca,
            traffic_patterns=tp,
        )
        lab.run()
    finally:
        _stop_live_modules(ct, dns, meta)


def cmd_graph(args, render_png: bool = False):
    """Network connection graph."""
    from rich.console import Console
    console = Console()

    ct, dns, meta = _start_live_modules(6.0)
    try:
        from analysis.network_graph import NetworkGraph
        from network.tracker_detector import TrackerDetector

        db_path = Path(__file__).parent / "data" / "tracker_domains.json"
        det = TrackerDetector(str(db_path) if db_path.exists() else None)
        tracker_db = det.build_flat_dict()

        graph = NetworkGraph()
        conns = ct.get_active_connections()
        if conns:
            graph.build_from_connections(conns, tracker_db=tracker_db)
        else:
            stats = dns.get_domain_stats(top=40)
            graph.build_from_dns_stats(stats, tracker_db=tracker_db)

        from rich.panel import Panel
        stats = graph.get_stats()

        if render_png:
            png = graph.render_png()
            if png:
                console.print(f"[green]Graph PNG saved → {png}[/green]")
            else:
                console.print("[yellow]matplotlib not available — showing ASCII tree[/yellow]\n")
                console.print(Panel(graph.ascii_tree(), title="Network Graph",
                                    border_style="cyan"))
        else:
            console.print(Panel(
                graph.ascii_tree(max_depth=2),
                title=f"Network Graph  Nodes:{stats['nodes']}  "
                      f"Edges:{stats['edges']}  Trackers:{stats['tracker_nodes']}",
                border_style="cyan",
            ))
    finally:
        _stop_live_modules(ct, dns, meta)


def cmd_analysis(args):
    """Connection analysis report."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()

    ct, dns, meta = _start_live_modules(8.0)
    try:
        from analysis.connection_analysis import ConnectionAnalyser
        ca = ConnectionAnalyser(window_secs=300.0)
        ca.ingest_connections(ct.get_active_connections())
        ca.ingest_dns_stats(dns.get_domain_stats(top=100))

        report = ca.analyse()

        console.print(Panel(
            f"Connections: {report.total_connections}  "
            f"Domains: {report.unique_domains}  "
            f"Trackers: [red]{report.tracker_domains}[/red]  "
            f"Port entropy: {report.port_entropy:.2f}",
            title="Connection Analysis",
            border_style="yellow",
        ))

        t = Table(title="Top 20 Domains", show_lines=True)
        t.add_column("Domain",  style="cyan", no_wrap=True)
        t.add_column("Count",   width=7)
        t.add_column("Tracker", style="red")
        for d in report.top_domains[:20]:
            t.add_row(d["domain"][:35], str(d["count"]),
                      d.get("tracker_name", "")[:25] if d["is_tracker"] else "")
        console.print(t)

        if report.c2_candidates:
            console.print(f"\n[bold red]⚠ C2 Candidates [{len(report.c2_candidates)}]:[/bold red]")
            for c in report.c2_candidates[:3]:
                console.print(f"  [{c.confidence}] {c.app} → {c.remote}")
                console.print(f"  {c.reason}\n")
    finally:
        _stop_live_modules(ct, dns, meta)


def cmd_patterns(args):
    """Traffic pattern heatmap."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    ct, dns, meta = _start_live_modules(8.0)
    try:
        from analysis.traffic_patterns import TrafficPatternAnalyser
        tp = TrafficPatternAnalyser()
        tp.ingest_connections(ct.get_active_connections())

        report = tp.analyse(window_secs=86400.0)
        heatmap = tp.get_ascii_heatmap(report)
        console.print(Panel(heatmap, title="Traffic Patterns", border_style="yellow"))
        console.print(
            f"[dim]Avg {report.avg_connections_per_min} conn/min  "
            f"Tracker ratio: {report.tracker_ratio:.1%}  "
            f"Protocol: {report.dominant_protocol}[/dim]"
        )
    finally:
        _stop_live_modules(ct, dns, meta)


def cmd_intel(args):
    """Threat intelligence dashboard."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()

    from intel.reputation_cache import ReputationCache
    rep = ReputationCache(enable_remote=True)
    stats = rep.get_stats()

    console.print(Panel(
        f"Cached entries: {stats['cached_entries']}\n"
        f"Malicious: [red]{stats['by_reputation'].get('MALICIOUS', 0)}[/red]\n"
        f"Suspicious: [yellow]{stats['by_reputation'].get('SUSPICIOUS', 0)}[/yellow]",
        title="Threat Intel Cache",
        border_style="cyan",
    ))

    if args.query:
        for ioc in args.query:
            entry = rep.lookup_sync(ioc)
            from ui.lab_view import SEVERITY_STYLE
            s = SEVERITY_STYLE.get(entry.reputation, "white")
            console.print(
                f"  {ioc:<35} [{s}]{entry.reputation}[/{s}]  "
                f"score={entry.score:.2f}  {', '.join(entry.sources) or 'no sources'}"
            )


def cmd_ioc(args, force_update: bool = False):
    """IOC database status and optional update."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    from intel.ioc_updater import IOCUpdater
    ioc = IOCUpdater()
    stats = ioc.get_stats()

    console.print(Panel(
        f"Total IOCs: {stats['total_iocs']}\n"
        f"By type: {stats['by_threat_type']}\n"
        f"Needs update: {'Yes' if ioc.needs_update() else 'No'}",
        title="IOC Database",
        border_style="cyan",
    ))

    if force_update:
        console.print("[dim]Downloading IOC feeds...[/dim]")
        results = ioc.update_now()
        for r in results:
            status = f"[green]+{r.added}[/green]" if r.success else f"[red]{r.error[:40]}[/red]"
            console.print(f"  {r.feed_name:25}  {status}  ({r.duration_secs}s)")


def cmd_apk(args):
    """APK static intelligence."""
    from rich.console import Console
    console = Console()

    if not args.apk:
        console.print("[red]Error: --apk <file> required[/red]")
        return

    from apk.apk_static_intel import APKStaticIntel
    analyser = APKStaticIntel()

    for apk_path in args.apk:
        console.print(f"\n[dim]Analysing {apk_path}...[/dim]")
        report = analyser.analyse(apk_path)

        if report.error:
            console.print(f"[red]{report.error}[/red]")
            continue

        from ui.lab_view import SEVERITY_STYLE
        rs = SEVERITY_STYLE.get(report.risk_level, "white")

        from rich.panel import Panel
        console.print(Panel(
            f"Package:     {report.package_name}\n"
            f"Version:     {report.version_name}\n"
            f"Size:        {report.file_size_kb} KB\n"
            f"SHA256:      {report.sha256[:32]}...\n"
            f"Risk:        [{rs}]{report.risk_level}[/{rs}] (score={report.risk_score})\n"
            f"Trackers:    {len(report.trackers)}\n"
            f"Secrets:     {len(report.secrets)}\n"
            f"Obfuscation: {report.obfuscation_score}/6",
            title=f"APK Intel — {Path(apk_path).name}",
            border_style=rs,
        ))
        for factor in report.risk_factors:
            console.print(f"  • {factor}")


def cmd_tracker_scan(args):
    """APK tracker SDK scanner."""
    from rich.console import Console
    console = Console()

    if not args.trackers:
        console.print("[red]Error: --trackers <file> required[/red]")
        return

    from apk.tracker_scanner import TrackerScanner
    scanner = TrackerScanner()

    for apk_path in args.trackers:
        console.print(f"\n[dim]Scanning {apk_path}...[/dim]")
        report = scanner.scan(apk_path)

        if report.scan_error:
            console.print(f"[red]{report.scan_error}[/red]")
            continue

        from ui.lab_view import SEVERITY_STYLE
        from rich.panel import Panel
        ps = SEVERITY_STYLE.get(report.privacy_score, "white")
        console.print(Panel(
            f"Package:  {report.package_name}\n"
            f"Trackers: {report.tracker_count}\n"
            f"Privacy:  [{ps}]{report.privacy_score}[/{ps}]",
            title=f"Tracker Scan — {Path(apk_path).name}",
            border_style=ps,
        ))
        for ev in report.trackers_found:
            rs = SEVERITY_STYLE.get(ev.risk, "white")
            console.print(f"  [{rs}]{ev.risk:<8}[/{rs}] {ev.name}  —  {ev.description}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DSRP Stage 4 — Security Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python lab_analysis.py              # Interactive Security Lab menu
  python lab_analysis.py --graph      # Network ASCII graph
  python lab_analysis.py --graph-png  # Network graph PNG
  python lab_analysis.py --analysis   # Connection analysis report
  python lab_analysis.py --patterns   # Traffic heatmap
  python lab_analysis.py --intel      # Threat intel dashboard
  python lab_analysis.py --intel --query 8.8.8.8 facebook.com
  python lab_analysis.py --ioc        # IOC database status
  python lab_analysis.py --ioc-update # Download IOC feeds
  python lab_analysis.py --apk app.apk
  python lab_analysis.py --trackers app.apk
        """
    )
    parser.add_argument("--graph",      action="store_true")
    parser.add_argument("--graph-png",  action="store_true")
    parser.add_argument("--analysis",   action="store_true")
    parser.add_argument("--patterns",   action="store_true")
    parser.add_argument("--intel",      action="store_true")
    parser.add_argument("--query",      nargs="+", metavar="IOC")
    parser.add_argument("--ioc",        action="store_true")
    parser.add_argument("--ioc-update", action="store_true")
    parser.add_argument("--apk",        nargs="+", metavar="FILE")
    parser.add_argument("--trackers",   nargs="+", metavar="FILE")

    args = parser.parse_args()

    if args.graph:
        cmd_graph(args, render_png=False)
    elif args.graph_png:
        cmd_graph(args, render_png=True)
    elif args.analysis:
        cmd_analysis(args)
    elif args.patterns:
        cmd_patterns(args)
    elif args.intel:
        cmd_intel(args)
    elif args.ioc or args.ioc_update:
        cmd_ioc(args, force_update=args.ioc_update)
    elif args.apk:
        cmd_apk(args)
    elif args.trackers:
        cmd_tracker_scan(args)
    else:
        cmd_lab(args)


if __name__ == "__main__":
    main()