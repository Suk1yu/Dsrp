#!/usr/bin/env python3
"""
dsrp.py — DSRP Unified Launcher
Device Security Research Platform v1.1
All 5 Stages in One Command

─────────────────────────────────────────────────────────────────
  Usage:
    python dsrp.py                      Full Textual Dashboard (all stages)
    python dsrp.py --lite               Rich fallback (no Textual needed)
    python dsrp.py --mode STRICT        Override defense mode
    python dsrp.py --stage 2            Run only Stage 2 (network)
    python dsrp.py --stage 3            Run only Stage 3 (security)
    python dsrp.py --stage 5            Run only Stage 5 (defense)
    python dsrp.py scan                 Quick app malware scan
    python dsrp.py network              Network analysis view
    python dsrp.py defend               Autonomous defense console
    python dsrp.py lab                  Security lab menu
    python dsrp.py report               Generate security report
    python dsrp.py block <ioc>          Block a domain or IP
    python dsrp.py unblock <ioc>        Unblock a domain or IP
    python dsrp.py status               System status snapshot
    python dsrp.py install              Show Termux install commands
─────────────────────────────────────────────────────────────────

Install in Termux:
  pkg install python nmap arp-scan -y
  pip install textual psutil rich scikit-learn networkx matplotlib requests
"""

import sys
import os
import time
import argparse
from pathlib import Path

# Ensure project root is in path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# ── Infrastructure boot (config → logging → resource limiter) ────────────────
# These three must be imported first so all other modules inherit the setup.
from config import cfg, dump_config, reload_config          # noqa: E402
from logger import setup_logging, get_logger                 # noqa: E402
from resource_limiter import limiter                         # noqa: E402

# Initialise logging from config
setup_logging(
    level          = cfg.logging.level,
    file_enabled   = cfg.logging.file_enabled,
    file_path      = str(ROOT / cfg.logging.file_path),
    max_bytes      = cfg.logging.max_file_size_mb * 1024 * 1024,
    backup_count   = cfg.logging.backup_count,
    show_module    = cfg.logging.show_module,
    console_enabled= True,
)

log = get_logger("dsrp")

# ─────────────────────────────────────────────────────────────────────────────
# Dependency check
# ─────────────────────────────────────────────────────────────────────────────

def _check_deps() -> dict:
    """Check which optional dependencies are available."""
    deps = {}
    for mod in ["textual", "rich", "psutil", "sklearn",
                "networkx", "matplotlib", "requests", "scapy"]:
        try:
            __import__(mod)
            deps[mod] = True
        except ImportError:
            deps[mod] = False
    return deps


def _print_install_guide():
    print("""
╔══════════════════════════════════════════════════════════════╗
║  DSRP — Termux Installation Guide                           ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  # Step 1: System packages                                   ║
║  pkg update && pkg upgrade -y                                ║
║  pkg install python nmap arp-scan iproute2 -y                ║
║                                                              ║
║  # Step 2: Core Python (required)                            ║
║  pip install psutil rich                                     ║
║                                                              ║
║  # Step 3: Textual UI (for full dashboard)                   ║
║  pip install textual                                         ║
║                                                              ║
║  # Step 4: AI/ML features                                    ║
║  pip install scikit-learn                                    ║
║                                                              ║
║  # Step 5: Network graph                                     ║
║  pip install networkx matplotlib                             ║
║                                                              ║
║  # Step 6: Threat intel API (optional)                       ║
║  pip install requests                                        ║
║  export VT_API_KEY="your_virustotal_key"                     ║
║  export ABUSEIPDB_API_KEY="your_abuseipdb_key"               ║
║                                                              ║
║  # Run                                                       ║
║  python dsrp.py                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


# ─────────────────────────────────────────────────────────────────────────────
# Rich fallback dashboard (no Textual needed)
# ─────────────────────────────────────────────────────────────────────────────

def run_rich_dashboard(core, mode: str):
    """Full-featured Rich live dashboard — fallback when Textual is absent."""
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich import box

    console = Console()
    console.print(f"\n[bold cyan]DSRP Unified Dashboard[/bold cyan]  "
                  f"[dim]Mode: {mode} | Ctrl+C to exit[/dim]\n")

    SEVERITY_STYLE = {
        "CRITICAL": "bold red", "HIGH": "red",
        "MEDIUM": "yellow", "LOW": "cyan",
    }

    def make_layout():
        layout = Layout()
        layout.split_column(
            Layout(name="top",    ratio=1),
            Layout(name="middle", ratio=1),
            Layout(name="bottom", ratio=1),
        )
        layout["top"].split_row(
            Layout(name="t1"), Layout(name="t2"), Layout(name="t3"))
        layout["middle"].split_row(
            Layout(name="m1"), Layout(name="m2"))
        layout["bottom"].split_row(
            Layout(name="b1"), Layout(name="b2"))
        return layout

    def sys_panel(d):
        cpu  = d.get("cpu", 0)
        ram  = d.get("ram_mb", 0)
        up   = d.get("net_up", 0)
        dn   = d.get("net_down", 0)
        cpu_c = "red" if cpu > 80 else "yellow" if cpu > 50 else "green"
        return Panel(
            f"[bold]CPU   [/{cpu_c}][{cpu_c}]{cpu:5.1f}%[/{cpu_c}]\n"
            f"[bold]RAM  [/bold] {ram:6.0f} MB\n"
            f"[bold]Net ↑[/bold] {up/1024:6.1f} KB/s\n"
            f"[bold]Net ↓[/bold] {dn/1024:6.1f} KB/s",
            title="[bold cyan]System[/bold cyan]",
            border_style="cyan",
        )

    def incidents_panel(d):
        incs = d.get("recent_incidents", [])
        t = Table(show_lines=False, expand=True, box=box.SIMPLE)
        t.add_column("", width=2)
        t.add_column("Time", width=8)
        t.add_column("Sev",  width=8)
        t.add_column("Description")
        for inc in reversed(incs[-6:]):
            sev = inc.get("severity","?")
            style = SEVERITY_STYLE.get(sev,"")
            badge = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(sev,"⚪")
            ts = time.strftime("%H:%M:%S", time.localtime(inc.get("timestamp",0)))
            t.add_row(badge, ts, f"[{style}]{sev[:4]}[/{style}]",
                      inc.get("description","")[:50])
        if not incs:
            t.add_row("⚪","","[green]CLEAN[/green]","No incidents")
        return Panel(t, title="[bold red]Incidents[/bold red]", border_style="red")

    def network_panel(d):
        t = Table(show_lines=False, expand=True, box=box.SIMPLE)
        t.add_column("Process", width=14, style="cyan")
        t.add_column("Remote",  width=22)
        t.add_column("Port",    width=6)
        t.add_column("⚠",       width=2)
        for c in d.get("connections", [])[:8]:
            flag = "⚠" if c.get("is_tracker") or c.get("is_suspicious") else ""
            host = (c.get("remote_hostname") or c.get("remote_ip","?"))[:22]
            t.add_row(c.get("process_name","?")[:14], host,
                      str(c.get("remote_port",0)), flag)
        if not d.get("connections"):
            t.add_row("[dim]collecting...[/dim]","","","")
        return Panel(t, title="[bold blue]Active Connections[/bold blue]",
                     border_style="blue")

    def trackers_panel(d):
        t = Table(show_lines=False, expand=True, box=box.SIMPLE)
        t.add_column("Domain",  style="red", no_wrap=True)
        t.add_column("Tracker", style="yellow")
        t.add_column("Ct",      width=4)
        for tr in d.get("tracker_domains", [])[:8]:
            t.add_row(tr.get("domain","")[:28],
                      tr.get("tracker_name","")[:20],
                      str(tr.get("count",0)))
        if not d.get("tracker_domains"):
            t.add_row("[dim]none detected[/dim]","","")
        return Panel(t, title="[bold yellow]Tracker Alerts[/bold yellow]",
                     border_style="yellow")

    def blocklist_panel(d):
        blocked = d.get("blocklist", [])
        bdom = d.get("blocked_domains", 0)
        bip  = d.get("blocked_ips", 0)
        t = Table(show_lines=False, expand=True, box=box.SIMPLE)
        t.add_column("Domain/IP", style="red", no_wrap=True)
        t.add_column("Type",      style="dim", width=10)
        for e in blocked[:6]:
            t.add_row(e.get("ioc","")[:28], e.get("threat_type","")[:10])
        if not blocked:
            t.add_row("[dim]nothing blocked[/dim]","")
        return Panel(t,
                     title=f"[bold red]Blocked [{bdom}d / {bip}ip][/bold red]",
                     border_style="red")

    def ids_panel(d):
        t = Table(show_lines=False, expand=True, box=box.SIMPLE)
        t.add_column("", width=2)
        t.add_column("Time", width=8)
        t.add_column("Rule", width=9, style="dim")
        t.add_column("Description")
        for a in d.get("ids_alerts",[])[-6:]:
            sev = a.get("severity","?")
            badge = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(sev,"⚪")
            ts = time.strftime("%H:%M:%S", time.localtime(a.get("timestamp",0)))
            t.add_row(badge, ts, a.get("rule_id","?"), a.get("description","")[:50])
        if not d.get("ids_alerts"):
            t.add_row("⚪","","","[green]No IDS alerts[/green]")
        return Panel(t, title="[bold red]IDS Alerts[/bold red]", border_style="red")

    def wifi_panel(d):
        devs = d.get("wifi_devices", [])
        t = Table(show_lines=False, expand=True, box=box.SIMPLE)
        t.add_column("IP", style="cyan", width=16)
        t.add_column("Name",   width=22)
        t.add_column("MAC",    style="dim")
        for dev in devs[:6]:
            t.add_row(dev.get("ip","?"), dev.get("display_name","?")[:22],
                      dev.get("mac","—"))
        if not devs:
            t.add_row("[dim]scan pending...[/dim]","","")
        return Panel(t, title="[bold green]WiFi Devices[/bold green]",
                     border_style="green")

    layout = make_layout()

    try:
        with Live(layout, refresh_per_second=0.4, screen=True, console=console):
            while True:
                d = core.collect_data()
                layout["t1"].update(sys_panel(d))
                layout["t2"].update(incidents_panel(d))
                layout["t3"].update(network_panel(d))
                layout["m1"].update(trackers_panel(d))
                layout["m2"].update(ids_panel(d))
                layout["b1"].update(blocklist_panel(d))
                layout["b2"].update(wifi_panel(d))
                time.sleep(3)
    except KeyboardInterrupt:
        core.stop_all()
        console.print("\n[yellow]DSRP stopped.[/yellow]")


# ─────────────────────────────────────────────────────────────────────────────
# Stage-only runners
# ─────────────────────────────────────────────────────────────────────────────

def run_stage(stage_num: int, mode: str):
    runners = {
        1: lambda: __import__("main").main(),
        2: lambda: __import__("network_analysis").main(),
        3: lambda: __import__("security_analysis").main(),
        4: lambda: __import__("lab_analysis").main(),
        5: lambda: __import__("autonomous_defense").main(),
    }
    if stage_num not in runners:
        print(f"Unknown stage: {stage_num}. Valid: 1–5")
        sys.exit(1)
    runners[stage_num]()


# ─────────────────────────────────────────────────────────────────────────────
# Status snapshot
# ─────────────────────────────────────────────────────────────────────────────

def print_status(deps: dict):
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from logger import get_log_stats
    from resource_limiter import LEVEL_LABELS
    console = Console()

    # Config summary
    console.print(Panel(dump_config(cfg), title="[bold cyan]Configuration[/bold cyan]",
                        border_style="cyan"))

    # Resource governor status
    snap = limiter.get_snapshot()
    if snap:
        level_color = {"NORMAL":"green","THROTTLE":"yellow",
                       "SKIP":"red","CRITICAL":"bold red"}.get(snap.label,"white")
        console.print(Panel(
            f"Level:  [{level_color}]{snap.label}[/{level_color}]\n"
            f"CPU:    {snap.cpu_percent:.1f}%\n"
            f"RAM:    {snap.ram_used_mb:.0f} / {snap.ram_total_mb:.0f} MB\n"
            f"Skipped tasks: {limiter.get_stats()['tasks_skipped']}",
            title="[bold yellow]Resource Governor[/bold yellow]",
            border_style="yellow",
        ))

    # Log file status
    log_stats = get_log_stats()
    console.print(Panel(
        f"Level:   {cfg.logging.level}\n"
        f"File:    {log_stats.get('file', 'disabled')}\n"
        f"Size:    {log_stats.get('size_kb', 0):.1f} KB",
        title="[bold green]Logging[/bold green]",
        border_style="green",
    ))

    # Dependencies
    t = Table(title="Dependency Status", show_lines=True)
    t.add_column("Package",   style="cyan")
    t.add_column("Status",    width=10)
    t.add_column("Used For")
    dep_info = {
        "textual":    ("Full Textual dashboard",         "pip install textual"),
        "rich":       ("All CLI views",                  "pip install rich"),
        "psutil":     ("System + network monitoring",    "pip install psutil"),
        "sklearn":    ("AI malware detection",           "pip install scikit-learn"),
        "networkx":   ("Network graph analysis",         "pip install networkx"),
        "matplotlib": ("Network graph PNG export",       "pip install matplotlib"),
        "requests":   ("Threat intel API lookups",       "pip install requests"),
        "scapy":      ("Deep packet capture (optional)", "pip install scapy"),
    }
    for pkg, (desc, install) in dep_info.items():
        ok = deps.get(pkg, False)
        status = "[green]✓ installed[/green]" if ok else f"[red]✗ missing[/red]"
        t.add_row(pkg, status, desc)
    console.print(t)

    console.print(Panel(
        "python dsrp.py              [dim]→ Full dashboard[/dim]\n"
        "python dsrp.py --lite       [dim]→ Rich fallback[/dim]\n"
        "python dsrp.py scan         [dim]→ App malware scan[/dim]\n"
        "python dsrp.py network      [dim]→ Network analysis[/dim]\n"
        "python dsrp.py defend       [dim]→ Autonomous defense[/dim]\n"
        "python dsrp.py lab          [dim]→ Security lab menu[/dim]\n"
        "python dsrp.py report       [dim]→ Generate report[/dim]\n"
        "python dsrp.py install      [dim]→ Install guide[/dim]",
        title="Quick Commands",
        border_style="cyan",
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="dsrp",
        description="DSRP — Device Security Research Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("command", nargs="?", default="dashboard",
                   choices=["dashboard","scan","network","defend","lab",
                            "report","block","unblock","status","install","speed","apk","vpn","ssl","wifi"],
                   help="Command to run (default: dashboard)")
    p.add_argument("args", nargs="*", help="Command arguments (e.g. domain to block)")
    p.add_argument("--mode",   default="DEFENSIVE",
                   choices=["MONITOR","DEFENSIVE","STRICT"],
                   help="Defense mode (default: DEFENSIVE)")
    p.add_argument("--stage",  type=int, choices=[1,2,3,4,5],
                   help="Run a specific stage only")
    p.add_argument("--lite",   action="store_true",
                   help="Use Rich fallback (no Textual required)")
    p.add_argument("--remote", action="store_true",
                   help="Enable remote threat intel API calls")
    p.add_argument("--no-ml",  action="store_true",
                   help="Disable ML features (faster startup)")
    return p


def main():
    deps = _check_deps()
    parser = build_arg_parser()
    args = parser.parse_args()

    # ── Stage-only shortcut ───────────────────────────────────────────
    if args.stage:
        run_stage(args.stage, args.mode)
        return

    # ── Subcommands that don't need full core ─────────────────────────
    if args.command == "install":
        _print_install_guide()
        return

    if args.command == "status":
        print_status(deps)
        return

    # ── Boot check ────────────────────────────────────────────────────
    if not deps["rich"] and not deps["textual"]:
        print("Error: install rich first:  pip install rich")
        sys.exit(1)

    # ── Subcommands with their own launchers ──────────────────────────
    if args.command == "vpn":
        from network.vpn_leak_detector import run_vpn_leak_test_cli
        run_vpn_leak_test_cli()
        return

    if args.command == "ssl":
        from network.ssl_tls_analyzer import run_ssl_live_scan_cli, run_ssl_apk_scan_cli
        apk_arg = next((a for a in sys.argv[2:] if a.endswith(".apk")), None)
        if apk_arg:
            run_ssl_apk_scan_cli(apk_arg)
        else:
            run_ssl_live_scan_cli()
        return

    if args.command == "wifi":
        from network.wifi_security_checker import run_wifi_security_scan_cli
        run_wifi_security_scan_cli()
        return

    if args.command == "speed":
        from network.speed_test import run_speed_test_cli
        run_speed_test_cli(run_upload="--no-upload" not in sys.argv)
        return

    if args.command == "apk":
        from apk.installed_apk_scanner import run_installed_scan
        run_installed_scan(max_apps=40)
        return

    if args.command == "scan":
        from security_analysis import cmd_scan
        cmd_scan(args)
        return

    if args.command == "network":
        from ui.network_view import run_network_view_cli
        run_network_view_cli()
        return

    if args.command == "defend":
        from autonomous_defense import cmd_console
        cmd_console(args)
        return

    if args.command == "lab":
        from lab_analysis import cmd_lab
        cmd_lab(args)
        return

    if args.command == "report":
        from autonomous_defense import cmd_report
        cmd_report(args)
        return

    if args.command == "block":
        if not args.args:
            print("Usage: python dsrp.py block <domain_or_ip>")
            return
        from core_engine import DSRPCore
        core = DSRPCore(defense_mode=args.mode)
        core._init_stage5()
        for ioc in args.args:
            core.block_domain(ioc, reason="manual block via CLI")
            print(f"Blocked: {ioc}")
        return

    if args.command == "unblock":
        if not args.args:
            print("Usage: python dsrp.py unblock <domain_or_ip>")
            return
        from core_engine import DSRPCore
        core = DSRPCore(defense_mode=args.mode)
        core._init_stage5()
        for ioc in args.args:
            core.unblock(ioc)
            print(f"Unblocked: {ioc}")
        return

    # ── Full dashboard ────────────────────────────────────────────────
    if not deps["rich"]:
        print("Error: pip install rich")
        sys.exit(1)

    from rich.console import Console
    console = Console()

    # Startup banner
    console.print("""
[bold #58A6FF]
▓█████▄   ██████  ██▀███   ██▓███  
▒██▀ ██▌▒██    ▒ ▓██ ▒ ██▒▓██░  ██▒
░██   █▌░ ▓██▄   ▓██ ░▄█ ▒▓██░ ██▓▒
░▓█▄   ▌  ▒   ██▒▒██▀▀█▄  ▒██▄█▓▒ ▒
░▒████▓ ▒██████▒▒░██▓ ▒██▒▒██▒ ░  ░
 ▒▒▓  ▒ ▒ ▒▓▒ ▒ ░░ ▒▓ ░▒▓░▒▓▒░ ░  ░
 ░ ▒  ▒ ░ ░▒  ░ ░  ░▒ ░ ▒░░▒ ░     
 ░ ░  ░ ░  ░  ░    ░░   ░ ░░       
   ░          ░     ░              
 ░                                 
[/bold #58A6FF]
[#6E7681]Device Security Research Platform v1.0[/#6E7681]
[#6E7681]All 5 Stages · Unified Dashboard[/#6E7681]
""")

    console.print(f"  Mode: [bold #F0B429]{args.mode}[/bold #F0B429]  "
                  f"  Lite: {'Yes' if args.lite else 'No'}  "
                  f"  Textual: {'Yes' if deps['textual'] else 'No (using Rich fallback)'}")
    console.print("  Starting modules...\n")

    # Build core
    from core_engine import DSRPCore
    core = DSRPCore(
        defense_mode=args.mode,
        enable_remote_intel=args.remote,
    )

    # Start background modules in a thread
    import threading
    threading.Thread(target=core.start_all, daemon=True).start()
    console.print("  [dim]Collecting initial data (3s)...[/dim]")
    time.sleep(3)

    # Launch dashboard
    if deps["textual"] and not args.lite:
        try:
            from ui.dashboard import DSRPDashboard
            app = DSRPDashboard(core=core)
            app.run()
        except Exception as e:
            console.print(f"[yellow]Textual error: {e}. Falling back to Rich.[/yellow]")
            run_rich_dashboard(core, args.mode)
    else:
        run_rich_dashboard(core, args.mode)

    core.stop_all()


if __name__ == "__main__":
    main()