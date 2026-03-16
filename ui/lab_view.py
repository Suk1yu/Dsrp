"""
ui/lab_view.py

Stage 4 Security Lab — Rich-powered analysis console.
Three sub-views: graph / intel / analysis
All views are on-demand (not continuous background rendering).

Usage:
  from ui.lab_view import SecurityLab
  lab = SecurityLab(conn_tracker, dns_monitor, rep_cache, ioc_updater)
  lab.run()
"""

import time
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.prompt import Prompt
    from rich import box
    from rich.columns import Columns
    RICH_OK = True
except ImportError:
    RICH_OK = False


SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "CLEAN":    "green",
    "INFO":     "dim",
}


class SecurityLab:
    """
    Interactive Security Lab console.
    Menu-driven: user selects analysis to run.
    """

    def __init__(self,
                 conn_tracker=None,
                 dns_monitor=None,
                 reputation_cache=None,
                 ioc_updater=None,
                 connection_analyser=None,
                 traffic_patterns=None):
        self._ct   = conn_tracker
        self._dns  = dns_monitor
        self._rep  = reputation_cache
        self._ioc  = ioc_updater
        self._ca   = connection_analyser
        self._tp   = traffic_patterns
        self._console = Console() if RICH_OK else None

    # ------------------------------------------------------------------
    # Main menu
    # ------------------------------------------------------------------

    def run(self):
        if not RICH_OK:
            print("Install rich: pip install rich")
            return

        c = self._console
        while True:
            c.print("\n[bold cyan]╔══════════════════════════════════════╗[/bold cyan]")
            c.print("[bold cyan]║   DSRP Stage 4 — Security Lab        ║[/bold cyan]")
            c.print("[bold cyan]╚══════════════════════════════════════╝[/bold cyan]\n")

            c.print("  [bold]1[/bold]  Network Graph (ASCII tree)")
            c.print("  [bold]2[/bold]  Connection Analysis Report")
            c.print("  [bold]3[/bold]  Traffic Pattern Heatmap")
            c.print("  [bold]4[/bold]  Threat Intelligence Dashboard")
            c.print("  [bold]5[/bold]  IOC Database Status & Update")
            c.print("  [bold]6[/bold]  APK Static Intelligence")
            c.print("  [bold]7[/bold]  APK Tracker Scanner")
            c.print("  [bold]8[/bold]  Render Network Graph PNG")
            c.print("  [bold]9[/bold]  🧹 Debloat Scanner")
            c.print("  [bold]0[/bold]  Exit\n")

            choice = Prompt.ask("Select", choices=["0","1","2","3","4","5","6","7","8","9"],
                                default="0")

            if choice == "0":
                break
            elif choice == "1":
                self._view_ascii_graph()
            elif choice == "2":
                self._view_connection_analysis()
            elif choice == "3":
                self._view_traffic_patterns()
            elif choice == "4":
                self._view_threat_intel()
            elif choice == "5":
                self._view_ioc_status()
            elif choice == "6":
                self._run_apk_intel()
            elif choice == "7":
                self._run_tracker_scan()
            elif choice == "8":
                self._render_graph_png()
            elif choice == "9":
                self._run_debloat_scan()

    # ------------------------------------------------------------------
    # View: ASCII graph
    # ------------------------------------------------------------------

    def _view_ascii_graph(self):
        c = self._console
        c.print("\n[bold cyan]Network Connection Graph[/bold cyan]\n")

        from analysis.network_graph import NetworkGraph
        from network.tracker_detector import TrackerDetector

        graph = NetworkGraph()
        db_path = Path(__file__).parent.parent / "data" / "tracker_domains.json"
        det = TrackerDetector(str(db_path) if db_path.exists() else None)
        tracker_db = det.build_flat_dict()

        if self._ct:
            conns = self._ct.get_active_connections()
            graph.build_from_connections(conns, tracker_db=tracker_db)
        elif self._dns:
            stats = self._dns.get_domain_stats(top=40)
            graph.build_from_dns_stats(stats, tracker_db=tracker_db)

        ascii_tree = graph.ascii_tree(max_depth=2)
        stats = graph.get_stats()

        c.print(Panel(
            ascii_tree,
            title=f"Network Graph  Nodes:{stats['nodes']}  "
                  f"Edges:{stats['edges']}  Trackers:{stats['tracker_nodes']}",
            border_style="cyan",
        ))

    # ------------------------------------------------------------------
    # View: Connection analysis
    # ------------------------------------------------------------------

    def _view_connection_analysis(self):
        c = self._console
        c.print("\n[bold yellow]Connection Analysis[/bold yellow]\n")

        from analysis.connection_analysis import ConnectionAnalyser

        ca = self._ca or ConnectionAnalyser(window_secs=300.0)

        if self._ct:
            ca.ingest_connections(self._ct.get_active_connections())
        if self._dns:
            ca.ingest_dns_stats(self._dns.get_domain_stats(top=100))

        report = ca.analyse()

        # Summary panel
        c.print(Panel(
            f"[bold]Window:[/bold]           {report.analysis_window_secs:.0f}s\n"
            f"[bold]Total Connections:[/bold] {report.total_connections}\n"
            f"[bold]Unique Domains:[/bold]    {report.unique_domains}\n"
            f"[bold]Unique IPs:[/bold]        {report.unique_ips}\n"
            f"[bold]Tracker Domains:[/bold]   [red]{report.tracker_domains}[/red]\n"
            f"[bold]Port Entropy:[/bold]      {report.port_entropy:.3f}\n"
            f"[bold]Dest Entropy:[/bold]      {report.destination_entropy:.3f}",
            title="Connection Summary",
            border_style="yellow",
        ))

        # Top domains table
        t = Table(title="Top Domains", show_lines=True, box=box.SIMPLE_HEAVY)
        t.add_column("Domain",   style="cyan", no_wrap=True)
        t.add_column("Count",    width=7)
        t.add_column("Type",     width=12)
        t.add_column("Tracker",  style="red")
        for d in report.top_domains[:15]:
            dtype = "[red]TRACKER[/red]" if d["is_tracker"] else "[green]clean[/green]"
            t.add_row(d["domain"][:35], str(d["count"]), dtype,
                      d.get("tracker_name", "")[:20])
        c.print(t)

        # Top ports
        t2 = Table(title="Top Ports", show_lines=True, box=box.SIMPLE)
        t2.add_column("Port",    width=7)
        t2.add_column("Count",   width=7)
        t2.add_column("Service", style="dim")
        for p in report.top_ports[:10]:
            t2.add_row(str(p["port"]), str(p["count"]), p["service"] or "—")
        c.print(t2)

        # C2 candidates
        if report.c2_candidates:
            c.print(f"\n[bold red]⚠ C2/Beaconing Candidates [{len(report.c2_candidates)}]:[/bold red]")
            for cand in report.c2_candidates[:5]:
                conf_style = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(
                    cand.confidence, "white")
                c.print(
                    f"  [{conf_style}]{cand.confidence}[/{conf_style}] "
                    f"[cyan]{cand.app}[/cyan] → [yellow]{cand.remote}[/yellow]\n"
                    f"    {cand.reason}"
                )

    # ------------------------------------------------------------------
    # View: Traffic patterns
    # ------------------------------------------------------------------

    def _view_traffic_patterns(self):
        c = self._console
        from analysis.traffic_patterns import TrafficPatternAnalyser

        tp = self._tp or TrafficPatternAnalyser()
        if self._ct:
            tp.ingest_connections(self._ct.get_active_connections())

        report = tp.analyse(window_secs=86400.0)
        heatmap = tp.get_ascii_heatmap(report)

        c.print(Panel(heatmap, title="Traffic Patterns", border_style="yellow"))

        c.print(
            f"\n[dim]Avg {report.avg_connections_per_min} conn/min  "
            f"Tracker ratio: {report.tracker_ratio:.1%}  "
            f"Dominant: {report.dominant_protocol}[/dim]"
        )

        if report.burst_events:
            c.print(f"\n[bold yellow]Burst Events [{len(report.burst_events)}]:[/bold yellow]")
            for b in report.burst_events[:5]:
                ts = time.strftime("%H:%M:%S", time.localtime(b.timestamp))
                c.print(f"  [yellow]{ts}[/yellow]  {b.peak_rate:.0f}/s  "
                        f"{b.total_connections} conns  {b.unique_destinations} destinations")

    # ------------------------------------------------------------------
    # View: Threat intelligence
    # ------------------------------------------------------------------

    def _view_threat_intel(self):
        c = self._console
        c.print("\n[bold cyan]Threat Intelligence Dashboard[/bold cyan]\n")

        if not self._rep:
            c.print("[yellow]Reputation cache not connected.[/yellow]")
            ioc_input = Prompt.ask("Enter IP or domain to lookup (or Enter to skip)",
                                   default="")
            if ioc_input:
                self._lookup_single(ioc_input)
            return

        malicious  = self._rep.get_malicious(limit=15)
        suspicious = self._rep.get_suspicious(limit=10)
        stats      = self._rep.get_stats()

        c.print(Panel(
            f"[bold]Cached entries:[/bold]   {stats['cached_entries']}\n"
            f"[bold]Malicious:[/bold]        [red]{stats['by_reputation'].get('MALICIOUS', 0)}[/red]\n"
            f"[bold]Suspicious:[/bold]       [yellow]{stats['by_reputation'].get('SUSPICIOUS', 0)}[/yellow]\n"
            f"[bold]Clean:[/bold]            [green]{stats['by_reputation'].get('CLEAN', 0)}[/green]\n"
            f"[bold]API calls today:[/bold]  {stats['api_calls_today']} / {stats['api_daily_limit']}",
            title="Reputation Cache Stats",
            border_style="cyan",
        ))

        if malicious:
            t = Table(title="Malicious IOCs", show_lines=True)
            t.add_column("IOC",   style="red",  no_wrap=True)
            t.add_column("Type",  width=8)
            t.add_column("Score", width=6)
            t.add_column("Sources")
            for e in malicious:
                t.add_row(e.ioc[:30], e.ioc_type, f"{e.score:.2f}",
                          ", ".join(e.sources)[:30])
            c.print(t)

        ioc_input = Prompt.ask(
            "\nLookup an IP/domain (or Enter to skip)", default="")
        if ioc_input:
            self._lookup_single(ioc_input)

    def _lookup_single(self, ioc: str):
        c = self._console
        if self._rep:
            entry = self._rep.lookup_sync(ioc)
        else:
            from intel.reputation_cache import ReputationCache
            entry = ReputationCache(enable_remote=True).lookup_sync(ioc)

        rep_style = SEVERITY_STYLE.get(entry.reputation, "white")
        c.print(Panel(
            f"[bold]IOC:[/bold]        {entry.ioc}\n"
            f"[bold]Type:[/bold]       {entry.ioc_type}\n"
            f"[bold]Reputation:[/bold] [{rep_style}]{entry.reputation}[/{rep_style}]\n"
            f"[bold]Score:[/bold]      {entry.score:.3f}\n"
            f"[bold]Sources:[/bold]    {', '.join(entry.sources) or 'none'}",
            title=f"Intel — {ioc}",
            border_style=rep_style,
        ))

    # ------------------------------------------------------------------
    # View: IOC updater status
    # ------------------------------------------------------------------

    def _view_ioc_status(self):
        c = self._console
        if not self._ioc:
            from intel.ioc_updater import IOCUpdater
            self._ioc = IOCUpdater()

        stats = self._ioc.get_stats()
        c.print(Panel(
            f"[bold]Total IOCs:[/bold]   {stats['total_iocs']}\n"
            f"[bold]Feeds:[/bold]        {stats['feeds_configured']}\n"
            f"[bold]By type:[/bold]      {stats['by_threat_type']}\n"
            f"[bold]Needs update:[/bold] {'Yes' if self._ioc.needs_update() else 'No'}",
            title="IOC Database",
            border_style="cyan",
        ))

        if Prompt.ask("Run feed update now?", choices=["y","n"], default="n") == "y":
            c.print("[dim]Downloading feeds...[/dim]")
            results = self._ioc.update_now()
            for r in results:
                status = "[green]OK[/green]" if r.success else f"[red]FAIL: {r.error}[/red]"
                c.print(f"  {r.feed_name:25}  {status}  +{r.added} IOCs  ({r.duration_secs}s)")

    def _run_debloat_scan(self):
        """Cross-platform debloat scan (replaces old Android-only version)."""
        c = self._console
        from system.debloat_cross import DebloatEngineCross
        engine = DebloatEngineCross()
        c.print(f"\n[dim]Scanning for bloatware ({engine.platform})...[/dim]")
        result = engine.scan()
        engine.print_scan_result(result)

        if result.items:
            from rich.prompt import Prompt as P
            choice = P.ask(
                "\nRemove items? (dry-run first)",
                choices=["dry", "no"], default="no"
            )
            if choice == "dry":
                for item in result.items:
                    r = engine.remove(item, dry_run=True)
                    c.print(f"  [dim]WOULD RUN:[/dim] {r.get('command','?')}")

    # ------------------------------------------------------------------
    # APK analysis
    # ------------------------------------------------------------------

    def _run_apk_intel(self):
        c = self._console
        apk_path = Prompt.ask("APK file path (drag & drop or type full path)")
        if not apk_path:
            return
        apk_path = apk_path.strip().strip('"\'')

        # Use cross-platform analyser (AXML binary manifest support)
        from apk.apk_analyzer_cross import APKAnalyzerCross
        c.print(f"\n[dim]Analysing {apk_path}...[/dim]")
        analyser = APKAnalyzerCross()
        report = analyser.analyse(apk_path)

        if report.error:
            c.print(f"[red]Error: {report.error}[/red]")
            return

        analyser.print_report(report)

        risk_style = SEVERITY_STYLE.get(report.risk_level, "white")

        c.print(Panel(
            f"[bold]Package:[/bold]        {report.package_name}\n"
            f"[bold]Version:[/bold]        {report.version_name} ({report.version_code})\n"
            f"[bold]Size:[/bold]           {report.file_size_kb} KB\n"
            f"[bold]SHA256:[/bold]         {report.sha256[:32]}...\n"
            f"[bold]DEX files:[/bold]      {report.dex_count} {'(multi-DEX)' if report.is_multi_dex else ''}\n"
            f"[bold]Native libs:[/bold]    {report.native_lib_count}\n"
            f"[bold]Risk Score:[/bold]     {report.risk_score}\n"
            f"[bold]Risk Level:[/bold]     [{risk_style}]{report.risk_level}[/{risk_style}]",
            title="APK Static Intelligence",
            border_style=risk_style,
        ))

        if report.risk_factors:
            c.print("\n[bold red]Risk Factors:[/bold red]")
            for f in report.risk_factors:
                c.print(f"  • {f}")

        if report.dangerous_permissions:
            c.print(f"\n[red]Dangerous Permissions ({report.dangerous_perm_count}):[/red]")
            for p in report.dangerous_permissions[:8]:
                c.print(f"  • {p}")

        if report.dangerous_apis:
            c.print(f"\n[red]Dangerous APIs ({len(report.dangerous_apis)}):[/red]")
            for api in report.dangerous_apis[:8]:
                style = SEVERITY_STYLE.get(api.severity, "")
                c.print(f"  [{style}]{api.severity:<8}[/{style}] {api.description}")

        if report.trackers:
            c.print(f"\n[yellow]Trackers ({len(report.trackers)}):[/yellow]")
            for t in report.trackers:
                c.print(f"  • {t.tracker_name}")

        if report.secrets:
            c.print(f"\n[red]Possible Secrets ({len(report.secrets)}):[/red]")
            for s in report.secrets[:5]:
                c.print(f"  • {s.pattern_name}: [dim]{s.sample}[/dim]")

        if report.embedded_ips:
            c.print(f"\n[yellow]Hardcoded IPs ({len(report.embedded_ips)}):[/yellow]")
            for ip in report.embedded_ips[:8]:
                c.print(f"  • {ip}")

    def _run_tracker_scan(self):
        c = self._console
        apk_path = Prompt.ask("APK file path")
        if not apk_path:
            return

        from apk.tracker_scanner import TrackerScanner
        c.print(f"\n[dim]Scanning trackers in {apk_path.strip()}...[/dim]")

        scanner = TrackerScanner()
        report = scanner.scan(apk_path.strip())

        if report.scan_error:
            c.print(f"[red]Error: {report.scan_error}[/red]")
            return

        ps_style = SEVERITY_STYLE.get(report.privacy_score, "white")
        c.print(Panel(
            f"[bold]Package:[/bold]          {report.package_name}\n"
            f"[bold]Trackers Found:[/bold]   {report.tracker_count}\n"
            f"[bold]Critical:[/bold]         [red]{len(report.critical_trackers)}[/red]\n"
            f"[bold]High Risk:[/bold]        [orange1]{len(report.high_risk_trackers)}[/orange1]\n"
            f"[bold]Categories:[/bold]       {report.tracker_categories}\n"
            f"[bold]Privacy Score:[/bold]    [{ps_style}]{report.privacy_score}[/{ps_style}]",
            title="Tracker Scan Report",
            border_style=ps_style,
        ))

        if report.trackers_found:
            t = Table(show_lines=True)
            t.add_column("Tracker",     style="yellow")
            t.add_column("Category",    width=18)
            t.add_column("Risk",        width=10)
            t.add_column("Confidence",  width=11)
            t.add_column("Description")
            for ev in sorted(report.trackers_found,
                             key=lambda x: x.risk, reverse=True):
                risk_style = SEVERITY_STYLE.get(ev.risk, "white")
                t.add_row(
                    ev.name,
                    ev.category,
                    f"[{risk_style}]{ev.risk}[/{risk_style}]",
                    f"{ev.confidence}%",
                    ev.description[:40],
                )
            c.print(t)

    # ------------------------------------------------------------------
    # Render PNG
    # ------------------------------------------------------------------

    def _render_graph_png(self):
        c = self._console
        c.print("\n[dim]Building graph for PNG render...[/dim]")

        from analysis.network_graph import NetworkGraph
        from network.tracker_detector import TrackerDetector

        graph = NetworkGraph()
        db_path = Path(__file__).parent.parent / "data" / "tracker_domains.json"
        det = TrackerDetector(str(db_path) if db_path.exists() else None)
        tracker_db = det.build_flat_dict()

        if self._ct:
            conns = self._ct.get_active_connections()
            graph.build_from_connections(conns, tracker_db=tracker_db)
        elif self._dns:
            stats = self._dns.get_domain_stats(top=40)
            graph.build_from_dns_stats(stats, tracker_db=tracker_db)

        png_path = graph.render_png()
        if png_path:
            c.print(f"[green]Graph saved → {png_path}[/green]")
        else:
            c.print("[yellow]PNG render requires matplotlib: pip install matplotlib[/yellow]")
            c.print("ASCII tree shown instead:\n")
            c.print(graph.ascii_tree())