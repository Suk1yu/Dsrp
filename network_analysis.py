#!/usr/bin/env python3
"""
network_analysis.py — Stage 2 Standalone Runner
Device Security Research Platform

Usage:
  python network_analysis.py              # Full live network view (rich)
  python network_analysis.py --tree       # ASCII connection tree snapshot
  python network_analysis.py --dns        # DNS monitor only
  python network_analysis.py --wifi       # WiFi device scan only
  python network_analysis.py --trackers   # Show tracker detections only
  python network_analysis.py --stats      # One-shot summary stats

CPU target: 2–5% on mobile ARM (Android / Termux)
"""

import argparse
import time
import sys
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent))


def cmd_tree():
    """Print ASCII connection map snapshot."""
    from ui.network_view import print_ascii_network_snapshot
    print_ascii_network_snapshot()


def cmd_live():
    """Full live rich network view."""
    from ui.network_view import run_network_view_cli
    run_network_view_cli()


def cmd_dns(duration: int = 30):
    """Monitor DNS queries for N seconds and show summary."""
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from network.dns_monitor import DNSMonitor
    from network.tracker_detector import TrackerDetector

    console = Console()
    db_path = Path(__file__).parent / "data" / "tracker_domains.json"
    detector = TrackerDetector(str(db_path) if db_path.exists() else None)

    monitor = DNSMonitor(poll_interval=2.0, tracker_db=detector.build_flat_dict())

    # Print new records as they arrive
    def on_record(record):
        flag = "[red]⚠ TRACKER[/red]" if record.is_tracker else "[green]ok[/green]"
        ts = time.strftime("%H:%M:%S", time.localtime(record.timestamp))
        console.print(f"[dim]{ts}[/dim]  {record.domain:<35} {flag}")

    monitor.add_callback(on_record)
    monitor.start()

    console.print(f"\n[bold cyan]DNS Monitor[/bold cyan] — watching for {duration}s\n")
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()

    # Summary
    console.print("\n[bold]Summary:[/bold]")
    summary = monitor.get_stats_summary()
    console.print(f"  Unique domains: {summary['unique_domains']}")
    console.print(f"  Total requests: {summary['total_requests']}")
    console.print(f"  Tracker domains: [red]{summary['tracker_domains']}[/red]")

    table = Table(title="Top Tracker Detections", show_lines=True)
    table.add_column("Domain", style="yellow")
    table.add_column("Tracker", style="red")
    table.add_column("Requests", width=9)
    for s in monitor.get_tracker_alerts(limit=15):
        table.add_row(s.domain, s.tracker_name, str(s.request_count))
    console.print(table)


def cmd_wifi(interval: int = 0):
    """WiFi device scan. If interval > 0, repeat every N seconds."""
    from network.network_mapper import NetworkMapper
    from rich.console import Console
    from rich.table import Table

    console = Console()
    mapper = NetworkMapper()
    console.print("\n[bold cyan]WiFi Device Discovery[/bold cyan]")

    def show_scan():
        console.print("[dim]Scanning...[/dim]")
        result = mapper.scan_now()
        table = Table(
            title=f"Devices [{len(result.devices)}]  method={result.scan_method}  "
                  f"time={result.duration_secs}s",
            show_lines=True
        )
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="dim")
        table.add_column("Name", width=25)
        table.add_column("Vendor", style="yellow")
        table.add_column("Ports")
        table.add_column("Seen")
        for dev in result.devices:
            table.add_row(*dev.to_row())
        console.print(table)

    show_scan()
    if interval > 0:
        console.print(f"\n[dim]Repeating every {interval}s — Ctrl+C to stop[/dim]")
        try:
            while True:
                time.sleep(interval)
                show_scan()
        except KeyboardInterrupt:
            pass


def cmd_trackers():
    """Show tracker domain database info + live detection."""
    from rich.console import Console
    from rich.table import Table
    from network.tracker_detector import TrackerDetector

    console = Console()
    db_path = Path(__file__).parent / "data" / "tracker_domains.json"
    detector = TrackerDetector(str(db_path) if db_path.exists() else None)

    console.print(f"\n[bold cyan]Tracker Database[/bold cyan]  "
                  f"[dim]{detector.count()} entries[/dim]\n")

    cats = detector.get_categories_summary()
    table = Table(title="Categories", show_lines=True)
    table.add_column("Category", style="yellow")
    table.add_column("Count", width=7)
    for cat, count in sorted(cats.items(), key=lambda x: x[1], reverse=True):
        table.add_row(cat, str(count))
    console.print(table)

    # Test some domains
    test_domains = [
        "api.mixpanel.com", "t.appsflyer.com", "google.com",
        "graph.facebook.com", "api.example.com", "doubleclick.net",
    ]
    console.print("\n[bold]Test lookups:[/bold]")
    for domain in test_domains:
        match = detector.check(domain)
        if match:
            console.print(f"  [red]⚠[/red] {domain:<35} → {match.tracker_name}")
        else:
            console.print(f"  [green]✓[/green] {domain:<35} → clean")


def cmd_stats():
    """One-shot stats snapshot."""
    from rich.console import Console
    from rich.panel import Panel
    from network.connection_tracker import ConnectionTracker
    from network.tracker_detector import TrackerDetector

    console = Console()
    db_path = Path(__file__).parent / "data" / "tracker_domains.json"
    detector = TrackerDetector(str(db_path) if db_path.exists() else None)

    ct = ConnectionTracker(poll_interval=5.0,
                           tracker_db=detector.build_flat_dict())
    ct.start()
    console.print("[dim]Collecting data (5s)...[/dim]")
    time.sleep(5.5)

    stats = ct.get_stats()
    groups = ct.get_connection_groups()
    tracker_conns = ct.get_tracker_connections()

    console.print(Panel(
        f"[bold]Active Apps:[/bold]        {stats['active_apps']}\n"
        f"[bold]Active Connections:[/bold] {stats['active_connections']}\n"
        f"[bold]Tracker Connections:[/bold] [red]{stats['tracker_connections']}[/red]",
        title="Network Stats Snapshot",
        border_style="cyan",
    ))

    if tracker_conns:
        console.print("\n[red]Tracker Connections:[/red]")
        for c in tracker_conns:
            console.print(f"  {c.app_name:<20} → [red]{c.tracker_name}[/red]  ({c.remote_hostname or c.remote_ip})")

    if groups:
        console.print("\n[cyan]Top 10 Active Processes:[/cyan]")
        for g in groups[:10]:
            t = f" [red]({g.tracker_count} trackers)[/red]" if g.tracker_count else ""
            console.print(f"  {g.app_name:<20} {g.total_remotes} connections{t}")

    ct.stop()


def main():
    parser = argparse.ArgumentParser(
        description="DSRP Stage 2 — Network Analysis Layer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_analysis.py              # Full live view
  python network_analysis.py --tree       # ASCII tree snapshot
  python network_analysis.py --dns 60     # Watch DNS for 60s
  python network_analysis.py --wifi       # Scan WiFi devices
  python network_analysis.py --wifi 120   # Scan every 120s
  python network_analysis.py --trackers   # Tracker DB info
  python network_analysis.py --stats      # Quick stats
        """
    )
    parser.add_argument("--tree", action="store_true",
                        help="Print ASCII connection tree snapshot")
    parser.add_argument("--dns", type=int, nargs="?", const=30, metavar="SECS",
                        help="DNS monitor (default 30s)")
    parser.add_argument("--wifi", type=int, nargs="?", const=0, metavar="INTERVAL",
                        help="WiFi scan (optional repeat interval)")
    parser.add_argument("--trackers", action="store_true",
                        help="Show tracker database and test lookups")
    parser.add_argument("--stats", action="store_true",
                        help="One-shot network stats snapshot")

    args = parser.parse_args()

    if args.vpn:
        from network.vpn_leak_detector import run_vpn_leak_test_cli
        run_vpn_leak_test_cli()
        return

    if args.ssl is not None:
        from network.ssl_tls_analyzer import run_ssl_live_scan_cli, run_ssl_apk_scan_cli
        if args.ssl and args.ssl != "live":
            run_ssl_apk_scan_cli(args.ssl)
        else:
            run_ssl_live_scan_cli()
        return

    if args.wifi:
        from network.wifi_security_checker import run_wifi_security_scan_cli
        run_wifi_security_scan_cli()
        return

    if args.speed:
        from network.speed_test import run_speed_test_cli
        run_speed_test_cli(run_upload=not args.no_upload)
        return

    if args.tree:
        cmd_tree()
    elif args.dns is not None:
        cmd_dns(args.dns)
    elif args.wifi is not None:
        cmd_wifi(args.wifi)
    elif args.trackers:
        cmd_trackers()
    elif args.stats:
        cmd_stats()
    else:
        cmd_live()


if __name__ == "__main__":
    main()