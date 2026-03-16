#!/usr/bin/env python3
"""
Device Security Research Platform (DSRP)
Main entry point - launches the Textual dashboard
"""

import asyncio
import sys
import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="Device Security Research Platform (DSRP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  dashboard     Full Textual GUI (default)
  scan          Quick CLI app scan
  network       Network scan only
  sniff         Packet sniffer (requires root)
  apk           APK static analysis
        """
    )
    parser.add_argument("mode", nargs="?", default="dashboard",
                        choices=["dashboard", "scan", "network", "sniff", "apk"],
                        help="Run mode (default: dashboard)")
    parser.add_argument("--apk", type=str, help="Path to APK file for analysis")
    parser.add_argument("--interface", type=str, default="wlan0",
                        help="Network interface for sniffing")
    parser.add_argument("--target", type=str, help="Target IP for network scan")
    parser.add_argument("--no-ml", action="store_true",
                        help="Disable ML features (faster startup)")
    return parser.parse_args()


def run_cli_scan():
    """Quick CLI scan without full GUI."""
    from rich.console import Console
    from rich.table import Table
    from core.app_analyzer import AppAnalyzer
    from core.behavior_engine import BehaviorEngine
    from core.malware_ml import MalwareMLEngine

    console = Console()
    console.print("\n[bold cyan]DSRP — Quick App Scan[/bold cyan]\n")

    analyzer = AppAnalyzer()
    engine = BehaviorEngine()
    ml = MalwareMLEngine()

    apps = analyzer.get_installed_packages()
    console.print(f"[green]Found {len(apps)} packages[/green]\n")

    table = Table(title="App Risk Summary", show_lines=True)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Risk", style="yellow")
    table.add_column("ML Score", style="magenta")
    table.add_column("Flags", style="red")

    for pkg in apps[:30]:
        profile = analyzer.analyze_package(pkg)
        risk = engine.evaluate(profile)
        ml_score = ml.predict(profile)
        flags = ", ".join(risk.get("flags", [])) or "—"
        level = risk.get("level", "LOW")
        color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}.get(level, "white")
        table.add_row(
            pkg,
            f"[{color}]{level}[/{color}]",
            f"{ml_score:.2f}",
            flags
        )

    console.print(table)


def run_apk_analysis(apk_path: str):
    """Run static APK analysis on a file."""
    from rich.console import Console
    from sandbox.apk_static_analyzer import APKStaticAnalyzer

    console = Console()
    console.print(f"\n[bold cyan]DSRP — APK Static Analysis[/bold cyan]")
    console.print(f"[dim]Target: {apk_path}[/dim]\n")

    analyzer = APKStaticAnalyzer()
    result = analyzer.analyze(apk_path)
    analyzer.print_report(result)


def run_dashboard():
    """Launch the full Textual dashboard."""
    from ui.dashboard import DSRPDashboard
    app = DSRPDashboard()
    app.run()


def main():
    args = parse_args()

    if args.mode == "scan":
        run_cli_scan()
    elif args.mode == "apk":
        if not args.apk:
            print("Error: --apk <path> required for apk mode")
            sys.exit(1)
        run_apk_analysis(args.apk)
    elif args.mode == "sniff":
        from network.packet_sniffer import PacketSniffer
        sniffer = PacketSniffer(interface=args.interface)
        sniffer.run_cli()
    elif args.mode == "network":
        from network.network_mapper import NetworkMapper
        mapper = NetworkMapper()
        mapper.run_cli(args.target)
    else:
        run_dashboard()


if __name__ == "__main__":
    main()