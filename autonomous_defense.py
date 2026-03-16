#!/usr/bin/env python3
"""
autonomous_defense.py — Stage 5 Standalone Runner
Android Security Research Platform — Autonomous Security & Self-Defense

Usage:
  python autonomous_defense.py              # Full defense console
  python autonomous_defense.py --mode <MODE>  # Set policy mode
  python autonomous_defense.py --block <domain/ip>
  python autonomous_defense.py --unblock <domain/ip>
  python autonomous_defense.py --blocklist    # Show blocklist
  python autonomous_defense.py --harden [SAFE|MODERATE|AGGRESSIVE]
  python autonomous_defense.py --harden-preview [LEVEL]
  python autonomous_defense.py --report       # Generate security report
  python autonomous_defense.py --incidents    # Show incident log
  python autonomous_defense.py --status       # System status

Modes: MONITOR | DEFENSIVE | STRICT

CPU target: ~2–5% additional on top of Stage 2/3 (event-driven, not polling)
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


# ---------------------------------------------------------------------------
# Module bootstrap
# ---------------------------------------------------------------------------

def _build_core(mode_str: str = "DEFENSIVE", enable_remote: bool = False):
    """Initialise all Stage 5 modules and return them as a namespace."""
    from types import SimpleNamespace
    from defense.policy_engine import PolicyEngine, PolicyMode
    from defense.auto_blocker import AutoBlocker
    from defense.response_engine import ResponseEngine
    from defense.privacy_hardener import PrivacyHardener
    from report.security_report import SecurityReportGenerator
    from report.incident_logger import IncidentLogger
    from intel.reputation_cache import ReputationCache

    try:
        mode = PolicyMode[mode_str.upper()]
    except KeyError:
        mode = PolicyMode.DEFENSIVE

    policy   = PolicyEngine(mode=mode)
    blocker  = AutoBlocker()
    resp     = ResponseEngine(policy=policy, blocker=blocker, mode=mode)
    hardener = PrivacyHardener()
    logger   = IncidentLogger()
    report_gen = SecurityReportGenerator()
    rep_cache  = ReputationCache(enable_remote=enable_remote)

    # Wire response engine → incident logger
    resp.add_callback(lambda incident: logger.log(incident))

    # Wire reputation cache hits → response engine
    rep_cache.add_callback(lambda entry: resp.on_reputation_hit(entry))

    return SimpleNamespace(
        policy=policy,
        blocker=blocker,
        response=resp,
        hardener=hardener,
        logger=logger,
        report_gen=report_gen,
        rep_cache=rep_cache,
        mode=mode,
    )


def _start_live_monitoring(core, duration: float = 6.0):
    """Start Stage 2 network modules and wire them into response engine."""
    from rich.console import Console
    console = Console()
    console.print(f"[dim]Starting live monitoring ({duration:.0f}s warm-up)...[/dim]")

    try:
        from network.connection_tracker import ConnectionTracker
        from network.dns_monitor import DNSMonitor
        from network.tracker_detector import TrackerDetector

        db_path = Path(__file__).parent / "data" / "tracker_domains.json"
        det = TrackerDetector(str(db_path) if db_path.exists() else None)
        tracker_db = det.build_flat_dict()

        ct  = ConnectionTracker(poll_interval=5.0, tracker_db=tracker_db)
        dns = DNSMonitor(poll_interval=3.0, tracker_db=tracker_db)

        # Wire DNS tracker hits to response engine
        def on_dns_record(record):
            if record.is_tracker:
                core.response.on_tracker_domain(
                    record.domain, record.tracker_name)
            # Check reputation cache (async)
            core.rep_cache.enqueue_lookup(record.domain)
            # Check blocklist
            if core.blocker.is_blocked(record.domain):
                console.print(
                    f"[red]⛔ BLOCKED DNS:[/red] {record.domain}")

        dns.add_callback(on_dns_record)
        ct.start()
        dns.start()
        time.sleep(duration)
        return ct, dns

    except Exception as e:
        console.print(f"[yellow]Live monitoring unavailable: {e}[/yellow]")
        return None, None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_console(args):
    """Full autonomous defense console."""
    from rich.console import Console
    console = Console()
    console.print("\n[bold cyan]DSRP Stage 5 — Autonomous Defense Console[/bold cyan]\n")

    core = _build_core(getattr(args, "mode", "DEFENSIVE"))
    ct, dns = _start_live_monitoring(core, duration=5.0)

    # Also hook into IDS (Stage 3) if available
    try:
        from ids.ids_engine import IDSEngine
        ids = IDSEngine()
        ids.add_callback(core.response.on_ids_alert)
        if ct:
            def on_conns(conns):
                for c in conns:
                    ids.process_connection(c)
            ct.add_callback(on_conns)
    except Exception:
        ids = None

    try:
        from ui.defense_view import run_defense_console
        run_defense_console(
            response_engine=core.response,
            blocker=core.blocker,
            policy=core.policy,
            hardener=core.hardener,
            incident_logger=core.logger,
            refresh_secs=3.0,
        )
    finally:
        for m in (ct, dns):
            if m:
                try: m.stop()
                except Exception: pass


def cmd_set_mode(args):
    from rich.console import Console
    console = Console()
    from defense.policy_engine import PolicyMode

    mode_str = args.mode.upper()
    if mode_str not in PolicyMode.__members__:
        console.print(f"[red]Invalid mode: {mode_str}[/red]")
        console.print("Valid modes: MONITOR, DEFENSIVE, STRICT")
        return

    core = _build_core(mode_str)
    mc = {"MONITOR": "cyan", "DEFENSIVE": "yellow", "STRICT": "red"}.get(mode_str, "white")
    console.print(f"Policy mode set to [{mc}]{mode_str}[/{mc}]")
    console.print("\nMode behaviours:")
    for k, v in core.policy.get_mode_summary()["rules"].items():
        state = "[green]ON[/green]" if v else "[dim]off[/dim]"
        console.print(f"  {k:<25} {state}")


def cmd_block(args):
    from rich.console import Console
    console = Console()
    core = _build_core()
    for ioc in args.block:
        ioc = ioc.strip()
        if ioc.replace(".", "").replace(":", "").isdigit():
            r = core.blocker.block_ip(ioc, reason="Manual block", source="manual")
        else:
            r = core.blocker.block_domain(ioc, reason="Manual block", source="manual")
        if r.already_blocked:
            console.print(f"[yellow]Already blocked:[/yellow] {ioc}")
        elif r.success:
            console.print(f"[red]Blocked:[/red] {ioc}  method={r.method}")
        else:
            console.print(f"[red]Failed to block {ioc}: {r.error}[/red]")


def cmd_unblock(args):
    from rich.console import Console
    console = Console()
    core = _build_core()
    for ioc in args.unblock:
        ok = core.blocker.unblock(ioc.strip())
        if ok:
            console.print(f"[green]Unblocked:[/green] {ioc}")
        else:
            console.print(f"[yellow]Not in blocklist:[/yellow] {ioc}")


def cmd_blocklist(args):
    from rich.console import Console
    from rich.table import Table
    console = Console()
    core = _build_core()
    stats = core.blocker.get_stats()

    console.print(
        f"\n[bold]Blocklist:[/bold] "
        f"[red]{stats['total_blocked']}[/red] total  "
        f"({stats['domains_blocked']} domains, {stats['ips_blocked']} IPs)\n"
    )

    domains = core.blocker.get_blocked_domains(limit=50)
    if domains:
        t = Table(title=f"Blocked Domains [{len(domains)}]", show_lines=True)
        t.add_column("Domain",    style="red", no_wrap=True)
        t.add_column("Threat",    width=14, style="dim")
        t.add_column("Source",    width=8)
        t.add_column("Reason")
        for e in domains:
            t.add_row(e.ioc, e.threat_type[:14], e.source[:8], e.reason[:35])
        console.print(t)

    ips = core.blocker.get_blocked_ips(limit=20)
    if ips:
        t2 = Table(title=f"Blocked IPs [{len(ips)}]", show_lines=True)
        t2.add_column("IP", style="red")
        t2.add_column("Threat"); t2.add_column("Source")
        for e in ips:
            t2.add_row(e.ioc, e.threat_type, e.source)
        console.print(t2)

    if not domains and not ips:
        console.print("[green]Blocklist is empty.[/green]")

    # Export option
    if getattr(args, "export", False):
        export_path = Path(__file__).parent / "data" / "blocklist.txt"
        export_path.write_text(core.blocker.export_hosts_format())
        console.print(f"\n[dim]Exported hosts format → {export_path}[/dim]")


def cmd_harden(args, preview_only: bool = False):
    from rich.console import Console
    from rich.table import Table
    console = Console()

    level_str = (getattr(args, "harden_level", None) or
                 getattr(args, "preview_level", None) or "SAFE").upper()
    valid_levels = ("SAFE", "MODERATE", "AGGRESSIVE")
    if level_str not in valid_levels:
        console.print(f"[red]Invalid level. Choose: {valid_levels}[/red]")
        return

    from defense.privacy_hardener import PrivacyHardener
    hardener = PrivacyHardener()
    counts = hardener.get_level_counts()

    console.print(f"\n[bold]Privacy Hardening — Level: {level_str}[/bold]")
    console.print(f"SAFE: {counts['SAFE']}  MODERATE: {counts['MODERATE']}  "
                  f"AGGRESSIVE: {counts['AGGRESSIVE']}\n")

    if preview_only:
        targets = hardener.preview(level_str)
        t = Table(title=f"Hardening Preview [{len(targets)}] level={level_str}",
                  show_lines=True)
        t.add_column("Package", style="cyan", no_wrap=True)
        t.add_column("Label")
        t.add_column("Level", width=10)
        t.add_column("Installed", width=9)
        t.add_column("Description")
        for target in targets:
            lc = {"SAFE": "green", "MODERATE": "yellow",
                  "AGGRESSIVE": "red"}.get(target["level"], "white")
            inst = "[green]Yes[/green]" if target["installed"] else "[dim]No[/dim]"
            t.add_row(target["package"][:35], target["label"][:20],
                      f"[{lc}]{target['level']}[/{lc}]",
                      inst, target["description"][:40])
        console.print(t)
        console.print("\n[dim]Run without --preview to execute[/dim]")
        return

    # Confirm
    from rich.prompt import Prompt
    confirm = Prompt.ask(
        f"Apply {level_str} hardening? ([bold]dry-run[/bold] first, then confirm)",
        choices=["y", "n"], default="n"
    )
    if confirm != "y":
        console.print("[yellow]Cancelled.[/yellow]")
        return

    # Dry run first
    console.print("\n[dim]Dry run...[/dim]")
    dry_report = hardener.harden(level_str, dry_run=True)
    console.print(f"Would disable {dry_report.succeeded} packages")

    confirm2 = Prompt.ask("Execute for real?", choices=["y", "n"], default="n")
    if confirm2 != "y":
        console.print("[yellow]Stopped at dry-run.[/yellow]")
        return

    report = hardener.harden(level_str, dry_run=False)
    console.print(
        f"\n[bold]Hardening complete:[/bold] "
        f"[green]{report.succeeded} succeeded[/green]  "
        f"[red]{report.failed} failed[/red]  "
        f"[dim]{report.skipped} skipped[/dim]  "
        f"({report.duration_secs}s)"
    )


def cmd_report(args):
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    console.print("\n[bold cyan]Generating Security Report...[/bold cyan]\n")

    core = _build_core()
    ct, dns = _start_live_monitoring(core, duration=8.0)

    try:
        from analysis.connection_analysis import ConnectionAnalyser
        ca = ConnectionAnalyser(window_secs=86400.0)
        if ct:
            ca.ingest_connections(ct.get_active_connections())
        if dns:
            ca.ingest_dns_stats(dns.get_domain_stats(top=100))

        report = core.report_gen.generate(
            window_hours=24.0,
            response_engine=core.response,
            ids_engine=None,
            connection_analyser=ca,
            blocker=core.blocker,
            hardener=core.hardener,
            reputation_cache=core.rep_cache,
        )

        # Print text report
        console.print(core.report_gen.render_text(report))

        # Save
        saved = core.report_gen.save(report, formats=["json", "txt", "md"])
        console.print("\n[bold]Report saved:[/bold]")
        for fmt, path in saved.items():
            console.print(f"  [{fmt}] {path}")

    finally:
        for m in (ct, dns):
            if m:
                try: m.stop()
                except Exception: pass


def cmd_incidents(args):
    from rich.console import Console
    from rich.table import Table
    console = Console()

    logger = _build_core().logger
    stats  = logger.get_stats()

    console.print(Panel(
        f"Total: {stats.get('total_incidents',0)}  "
        f"By severity: {stats.get('by_severity',{})}",
        title="Incident Log", border_style="cyan",
    ))

    incidents = logger.get_recent(n=30)
    if not incidents:
        console.print("[green]No incidents logged.[/green]")
        return

    t = Table(show_lines=False, expand=True)
    t.add_column("Time",   width=9)
    t.add_column("Sev",    width=8)
    t.add_column("Source", width=10)
    t.add_column("Description")
    t.add_column("Actions", style="dim")
    for inc in reversed(incidents):
        style = {"CRITICAL": "bold red", "HIGH": "red",
                 "MEDIUM": "yellow", "LOW": "cyan"}.get(inc.severity, "")
        ts = time.strftime("%H:%M:%S", time.localtime(inc.timestamp))
        t.add_row(
            ts,
            f"[{style}]{inc.severity[:4]}[/{style}]",
            inc.source[:9],
            inc.description[:60],
            inc.actions[:20],
        )
    console.print(t)


def cmd_status(args):
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    core = _build_core()
    bstats = core.blocker.get_stats()
    lstats = core.logger.get_stats()
    hcounts = core.hardener.get_level_counts()

    console.print(Panel(
        f"[bold]Policy Mode:[/bold]       {core.mode.value}\n"
        f"[bold]Blocked Domains:[/bold]   {bstats.get('domains_blocked',0)}\n"
        f"[bold]Blocked IPs:[/bold]       {bstats.get('ips_blocked',0)}\n"
        f"[bold]Total Incidents:[/bold]   {lstats.get('total_incidents',0)}\n"
        f"[bold]Hardening Targets:[/bold] "
        f"SAFE={hcounts['SAFE']} MODERATE={hcounts['MODERATE']} "
        f"AGGRESSIVE={hcounts['AGGRESSIVE']}",
        title="DSRP Stage 5 — Status",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DSRP Stage 5 — Autonomous Security & Self-Defense",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes: MONITOR | DEFENSIVE | STRICT

Examples:
  python autonomous_defense.py                     # Full defense console
  python autonomous_defense.py --mode STRICT       # Run in strict mode
  python autonomous_defense.py --block malware.com 1.2.3.4
  python autonomous_defense.py --unblock malware.com
  python autonomous_defense.py --blocklist
  python autonomous_defense.py --blocklist --export
  python autonomous_defense.py --harden-preview SAFE
  python autonomous_defense.py --harden SAFE
  python autonomous_defense.py --report
  python autonomous_defense.py --incidents
  python autonomous_defense.py --status
        """
    )
    parser.add_argument("--mode",     metavar="MODE", help="Set policy mode")
    parser.add_argument("--block",    nargs="+", metavar="IOC")
    parser.add_argument("--unblock",  nargs="+", metavar="IOC")
    parser.add_argument("--blocklist", action="store_true")
    parser.add_argument("--export",   action="store_true",
                        help="Export blocklist in hosts format")
    parser.add_argument("--harden",   nargs="?", const="SAFE",
                        metavar="LEVEL", dest="harden_level")
    parser.add_argument("--harden-preview", nargs="?", const="SAFE",
                        metavar="LEVEL", dest="preview_level")
    parser.add_argument("--report",    action="store_true")
    parser.add_argument("--incidents", action="store_true")
    parser.add_argument("--status",    action="store_true")

    args = parser.parse_args()

    if args.block:
        cmd_block(args)
    elif args.unblock:
        cmd_unblock(args)
    elif args.blocklist:
        cmd_blocklist(args)
    elif args.preview_level is not None:
        cmd_harden(args, preview_only=True)
    elif args.harden_level is not None:
        cmd_harden(args, preview_only=False)
    elif args.mode and not any([args.block, args.unblock, args.blocklist]):
        cmd_set_mode(args)
    elif args.report:
        cmd_report(args)
    elif args.incidents:
        cmd_incidents(args)
    elif args.status:
        cmd_status(args)
    else:
        cmd_console(args)


if __name__ == "__main__":
    main()