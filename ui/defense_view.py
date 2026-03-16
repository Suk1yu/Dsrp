"""
ui/defense_view.py

Stage 5 Defense Dashboard — Rich live console.
Shows: defense mode, blocked domains, active policy, recent incidents.
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
    RICH_OK = True
except ImportError:
    RICH_OK = False


MODE_COLOR = {
    "MONITOR":   "cyan",
    "DEFENSIVE": "yellow",
    "STRICT":    "red",
}

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}


def run_defense_console(
        response_engine=None,
        blocker=None,
        policy=None,
        hardener=None,
        incident_logger=None,
        refresh_secs: float = 3.0,
):
    """Full-screen live defense console."""
    if not RICH_OK:
        print("Install rich: pip install rich")
        return

    console = Console()

    def build_layout():
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
        )
        layout["main"].split_row(
            Layout(name="left",  ratio=1),
            Layout(name="center", ratio=1),
            Layout(name="right", ratio=1),
        )
        return layout

    def header_panel():
        mode = "MONITOR"
        if response_engine:
            mode = response_engine.get_status().get("mode", "MONITOR")
        elif policy:
            mode = policy.mode.value

        mc = MODE_COLOR.get(mode, "white")
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        status_text = (
            f"[bold cyan]DSRP Stage 5 — Defense Console[/bold cyan]  "
            f"[dim]{now}[/dim]  │  "
            f"Mode: [{mc}]{mode}[/{mc}]"
        )
        if response_engine:
            m = response_engine.get_metrics()
            status_text += (
                f"  │  Incidents: [yellow]{m.get('incidents_total',0)}[/yellow]"
                f"  Blocks: [red]{m.get('blocks_executed',0)}[/red]"
            )
        return Panel(status_text, style="blue", padding=(0, 1))

    def incidents_panel():
        table = Table(title="Recent Incidents", title_style="bold red",
                      show_lines=False, expand=True, box=box.SIMPLE_HEAVY)
        table.add_column("", width=2)
        table.add_column("Time", width=8)
        table.add_column("Sev", width=8)
        table.add_column("Source", width=10)
        table.add_column("Description", no_wrap=False)

        incidents = []
        if incident_logger:
            incidents = incident_logger.get_recent(n=15)
        elif response_engine:
            incidents = response_engine.get_recent_incidents(n=15)

        for inc in reversed(incidents[-15:]):
            style = SEVERITY_STYLE.get(inc.severity, "")
            ts = time.strftime("%H:%M:%S", time.localtime(inc.timestamp))
            badge = {"CRITICAL": "🔴", "HIGH": "🟠",
                     "MEDIUM": "🟡", "LOW": "🔵"}.get(inc.severity, "⚪")
            src = getattr(inc, "source", "?")[:9]
            desc = getattr(inc, "description", "")[:60]
            table.add_row(badge, ts,
                          f"[{style}]{inc.severity[:4]}[/{style}]",
                          src, desc)

        if not incidents:
            table.add_row("", "", "[green]CLEAN[/green]", "", "No incidents yet")
        return Panel(table, border_style="red")

    def blocklist_panel():
        table = Table(title="Blocked Domains (recent)",
                      title_style="bold yellow",
                      show_lines=False, expand=True, box=box.SIMPLE)
        table.add_column("Domain",    style="red", no_wrap=True)
        table.add_column("Reason",    style="dim")
        table.add_column("Source",    width=8)

        if blocker:
            entries = blocker.get_blocked_domains(limit=15)
            for e in entries[-15:]:
                table.add_row(
                    e.ioc[:30],
                    e.threat_type[:20] or e.reason[:20],
                    e.source[:8],
                )
            if not entries:
                table.add_row("[dim]No domains blocked[/dim]", "", "")
        else:
            table.add_row("[dim]Blocker not connected[/dim]", "", "")

        return Panel(table, border_style="yellow")

    def policy_panel():
        lines = []

        # Mode
        mode = "MONITOR"
        if response_engine:
            mode = response_engine.get_status().get("mode", "MONITOR")
        elif policy:
            mode = policy.mode.value

        mc = MODE_COLOR.get(mode, "white")
        lines.append(f"Mode: [{mc}]{mode}[/{mc}]")
        lines.append("")

        # Blocker stats
        if blocker:
            bs = blocker.get_stats()
            lines.append(f"[bold]Blocked:[/bold]")
            lines.append(f"  Domains : [red]{bs.get('domains_blocked',0)}[/red]")
            lines.append(f"  IPs     : [red]{bs.get('ips_blocked',0)}[/red]")
            lines.append(f"  Checks  : {bs.get('checks_performed',0)}")
            lines.append("")

        # Flagged apps
        if response_engine:
            flagged = response_engine.get_flagged_apps()
            if flagged:
                lines.append(f"[bold red]Flagged Apps ({len(flagged)}):[/bold red]")
                for app in list(flagged)[:5]:
                    lines.append(f"  ⚠ {app[:25]}")
                lines.append("")

        # Hardening
        if hardener:
            hardened = hardener.get_hardened_packages()
            lines.append(
                f"[bold]Hardening:[/bold] "
                f"{'[green]Active[/green]' if hardened else '[dim]Off[/dim]'}  "
                f"({len(hardened)} pkgs)"
            )

        return Panel("\n".join(lines), title="Defense Status",
                     border_style="green")

    layout = build_layout()
    console.print("[bold cyan]DSRP Stage 5 — Defense Console[/bold cyan]  "
                  "[dim]Ctrl+C to exit[/dim]")

    try:
        with Live(layout, refresh_per_second=1/refresh_secs,
                  screen=True, console=console):
            while True:
                layout["header"].update(header_panel())
                layout["center"].update(incidents_panel())
                layout["right"].update(blocklist_panel())
                layout["left"].update(policy_panel())
                time.sleep(refresh_secs)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# One-shot CLI summary
# ---------------------------------------------------------------------------

def print_defense_summary(response_engine=None, blocker=None,
                           incident_logger=None, hardener=None):
    if not RICH_OK:
        return
    console = Console()

    console.print("\n[bold cyan]DSRP Defense Summary[/bold cyan]\n")

    if response_engine:
        status = response_engine.get_status()
        m = response_engine.get_metrics()
        mc = MODE_COLOR.get(status.get("mode", "MONITOR"), "white")
        console.print(Panel(
            f"[bold]Mode:[/bold]             [{mc}]{status.get('mode')}[/{mc}]\n"
            f"[bold]Incidents Total:[/bold]  {m.get('incidents_total',0)}\n"
            f"[bold]Blocks Executed:[/bold]  [red]{m.get('blocks_executed',0)}[/red]\n"
            f"[bold]Apps Flagged:[/bold]     {m.get('apps_flagged',0)}\n"
            f"[bold]Domains Blocked:[/bold]  {status.get('blocked_domains',0)}\n"
            f"[bold]IPs Blocked:[/bold]      {status.get('blocked_ips',0)}",
            title="Response Engine",
            border_style="cyan",
        ))

        incidents = response_engine.get_recent_incidents(20)
        if incidents:
            table = Table(title="Recent Incidents", show_lines=True)
            table.add_column("Severity", width=10)
            table.add_column("Source",   width=11)
            table.add_column("Description")
            table.add_column("Actions")
            for inc in reversed(incidents[-10:]):
                style = SEVERITY_STYLE.get(inc.severity, "")
                actions = ", ".join(inc.actions_taken) if inc.actions_taken else "—"
                table.add_row(
                    f"[{style}]{inc.severity}[/{style}]",
                    inc.source[:10],
                    inc.description[:55],
                    actions[:25],
                )
            console.print(table)

    if blocker:
        blocked = blocker.get_blocked_domains(limit=10)
        if blocked:
            console.print(f"\n[red]Blocked Domains [{len(blocked)}]:[/red]")
            for e in blocked:
                console.print(f"  ✗ {e.ioc:<30} [{e.threat_type}]")

    if hardener:
        hardened = hardener.get_hardened_packages()
        if hardened:
            console.print(f"\n[green]Hardened Packages [{len(hardened)}]:[/green]")
            for pkg in list(hardened)[:5]:
                console.print(f"  ✓ {pkg}")