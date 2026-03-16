"""
ui/dashboard.py

DSRP Full Textual Dashboard — All 5 Stages in One Screen.

Layout:
  ┌─────────────────────────────────────────────────────────────┐
  │  DSRP  Android Security Research Platform    [mode] [status] │
  ├──────┬──────────────────────────────────────────────────────┤
  │ NAV  │                   MAIN PANEL                         │
  │      │  [Dashboard] [Network] [Security] [Defense] [Lab]    │
  │  ●   │                                                       │
  │  ●   │                                                       │
  │  ●   │                                                       │
  ├──────┴──────────────────────────────────────────────────────┤
  │  [q]uit  [r]efresh  [m]ode  [s]can  [b]lock  [?]help        │
  └─────────────────────────────────────────────────────────────┘

Tabs: Dashboard | Network | Security | Defense | Lab | Report
"""

from __future__ import annotations

import time
import threading
from pathlib import Path
from typing import Optional

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
    from textual.widgets import (
        Header, Footer, Static, DataTable, Label,
        Button, TabbedContent, TabPane, ProgressBar,
        Log, Sparkline, Digits,
    )
    from textual.reactive import reactive
    from textual.timer import Timer
    from textual import events
    from textual.screen import Screen
    from textual.css.query import NoMatches
    TEXTUAL_OK = True
except ImportError:
    TEXTUAL_OK = False

DSRP_CSS = """
/* ── Global ───────────────────────────────────────────────────────── */
Screen {
    background: #0D1117;
}

/* ── Header ───────────────────────────────────────────────────────── */
#header-bar {
    height: 3;
    background: #161B22;
    border-bottom: solid #30363D;
    padding: 0 2;
    layout: horizontal;
    align: left middle;
}

#header-logo {
    color: #58A6FF;
    text-style: bold;
    width: auto;
}

#header-mode {
    margin-left: 2;
    color: #F0B429;
    text-style: bold;
    width: auto;
}

#header-status {
    dock: right;
    color: #3FB950;
    width: auto;
    margin-right: 2;
}

/* ── Sidebar ──────────────────────────────────────────────────────── */
#sidebar {
    width: 18;
    background: #0D1117;
    border-right: solid #21262D;
    padding: 1 0;
}

.nav-item {
    height: 3;
    padding: 0 2;
    color: #8B949E;
    background: #0D1117;
}

.nav-item:hover {
    background: #161B22;
    color: #C9D1D9;
}

.nav-item.active {
    background: #1F3547;
    color: #58A6FF;
    border-left: solid #1F6FEB;
    text-style: bold;
}

#sidebar-stats {
    margin-top: 1;
    padding: 0 2;
    color: #6E7681;
    height: auto;
}

/* ── Main content ─────────────────────────────────────────────────── */
#main-area {
    background: #0D1117;
}

TabbedContent {
    background: #0D1117;
}

TabPane {
    background: #0D1117;
    padding: 1;
}

/* ── Panels / cards ───────────────────────────────────────────────── */
.panel {
    background: #161B22;
    border: solid #30363D;
    padding: 1;
    margin: 0 0 1 0;
}

.panel-title {
    color: #58A6FF;
    text-style: bold;
    margin-bottom: 1;
}

/* ── Status colors ────────────────────────────────────────────────── */
.critical { color: #FF7B72; text-style: bold; }
.high     { color: #F0B429; }
.medium   { color: #D29922; }
.low      { color: #58A6FF; }
.clean    { color: #3FB950; }
.dim-text { color: #6E7681; }
.tracker  { color: #FF7B72; }

/* ── DataTable ────────────────────────────────────────────────────── */
DataTable {
    background: #161B22;
    height: auto;
    max-height: 20;
}

DataTable > .datatable--header {
    background: #21262D;
    color: #8B949E;
}

DataTable > .datatable--cursor {
    background: #1F3547;
    color: #C9D1D9;
}

/* ── Metrics row ──────────────────────────────────────────────────── */
.metrics-row {
    height: 5;
    layout: horizontal;
    margin-bottom: 1;
}

.metric-card {
    background: #161B22;
    border: solid #30363D;
    padding: 0 2;
    margin: 0 1 0 0;
    align: center middle;
    width: 1fr;
}

.metric-value {
    color: #58A6FF;
    text-style: bold;
    text-align: center;
}

.metric-label {
    color: #6E7681;
    text-align: center;
}

/* ── Log widget ───────────────────────────────────────────────────── */
Log {
    background: #0D1117;
    color: #C9D1D9;
    border: solid #21262D;
    height: 12;
}

/* ── Buttons ──────────────────────────────────────────────────────── */
Button {
    background: #21262D;
    color: #C9D1D9;
    border: solid #30363D;
    margin: 0 1;
}

Button:hover {
    background: #30363D;
    border: solid #58A6FF;
}

Button.-primary {
    background: #1F6FEB;
    color: #FFFFFF;
}

Button.-warning {
    background: #9E6A03;
    color: #FFFFFF;
}

Button.-error {
    background: #B91C1C;
    color: #FFFFFF;
}

/* ── Footer ───────────────────────────────────────────────────────── */
Footer {
    background: #161B22;
    color: #6E7681;
    border-top: solid #30363D;
}
"""

if TEXTUAL_OK:

    class MetricCard(Static):
        """A single metric display card."""

        DEFAULT_CSS = """
        MetricCard {
            background: #161B22;
            border: solid #30363D;
            padding: 0 1;
            margin: 0 1 0 0;
            align: center middle;
            width: 1fr;
            height: 5;
        }
        """

        def __init__(self, label: str, value: str = "—",
                     color: str = "#58A6FF", **kwargs):
            super().__init__(**kwargs)
            self._label = label
            self._value = value
            self._color = color

        def compose(self) -> ComposeResult:
            yield Label(f"[bold {self._color}]{self._value}[/bold {self._color}]",
                        id="mv")
            yield Label(f"[#6E7681]{self._label}[/#6E7681]", id="ml")

        def update_value(self, value: str, color: str = None):
            self._value = value
            if color:
                self._color = color
            try:
                self.query_one("#mv", Label).update(
                    f"[bold {self._color}]{value}[/bold {self._color}]")
            except Exception:
                pass

    class DashboardTab(Static):
        """Overview of all metrics from all stages."""

        def compose(self) -> ComposeResult:
            yield Label("[bold #58A6FF]System Overview[/bold #58A6FF]\n",
                        classes="panel-title")

            with Horizontal(classes="metrics-row"):
                yield MetricCard("Incidents", "0",   "#FF7B72", id="mc-incidents")
                yield MetricCard("Blocked",   "0",   "#F0B429", id="mc-blocked")
                yield MetricCard("Trackers",  "0",   "#D29922", id="mc-trackers")
                yield MetricCard("Apps Scanned", "0", "#3FB950", id="mc-apps")

            with Horizontal(classes="metrics-row"):
                yield MetricCard("CPU",       "—%",  "#58A6FF", id="mc-cpu")
                yield MetricCard("RAM",       "—MB", "#58A6FF", id="mc-ram")
                yield MetricCard("Net ↑",     "—",   "#3FB950", id="mc-netup")
                yield MetricCard("Net ↓",     "—",   "#3FB950", id="mc-netdn")

            with Horizontal(classes="metrics-row"):
                yield MetricCard("Governor",  "NORMAL", "#3FB950", id="mc-gov")
                yield MetricCard("Skipped",   "0",   "#6E7681", id="mc-skip")

            yield Label("\n[bold #58A6FF]Recent Alerts[/bold #58A6FF]",
                        classes="panel-title")
            yield DataTable(id="dash-alerts-table")

        def on_mount(self):
            t = self.query_one("#dash-alerts-table", DataTable)
            t.add_columns("⚑", "Time", "Severity", "Source", "Description")
            t.add_row("⚪", "—", "—", "—", "Waiting for data...")

        def refresh_data(self, app_ref):
            d = app_ref.engine_data


            try:
                self.query_one("#mc-incidents", MetricCard).update_value(
                    str(d.get("incidents_total", 0)), "#FF7B72"
                    if d.get("incidents_total", 0) > 0 else "#3FB950")
            except Exception:
                pass
            try:
                self.query_one("#mc-blocked", MetricCard).update_value(
                    str(d.get("blocked_total", 0)))
            except Exception:
                pass
            try:
                self.query_one("#mc-trackers", MetricCard).update_value(
                    str(d.get("tracker_count", 0)))
            except Exception:
                pass
            try:
                self.query_one("#mc-apps", MetricCard).update_value(
                    str(d.get("apps_scanned", 0)))
            except Exception:
                pass
            try:
                cpu = d.get("cpu", 0)
                self.query_one("#mc-cpu", MetricCard).update_value(
                    f"{cpu:.0f}%",
                    "#FF7B72" if cpu > 80 else "#58A6FF")
            except Exception:
                pass
            try:
                self.query_one("#mc-ram", MetricCard).update_value(
                    f"{d.get('ram_mb', 0):.0f}MB")
            except Exception:
                pass
            try:
                self.query_one("#mc-netup", MetricCard).update_value(
                    _fmt_rate(d.get("net_up", 0)))
            except Exception:
                pass
            try:
                self.query_one("#mc-netdn", MetricCard).update_value(
                    _fmt_rate(d.get("net_down", 0)))
            except Exception:
                pass
            
            try:
                gov_level = d.get("resource_level", "NORMAL")
                gov_color = {
                    "NORMAL":   "#3FB950",
                    "THROTTLE": "#F0B429",
                    "SKIP":     "#FF7B72",
                    "CRITICAL": "#FF7B72",
                }.get(gov_level, "#C9D1D9")
                self.query_one("#mc-gov", MetricCard).update_value(
                    gov_level, gov_color)
                self.query_one("#mc-skip", MetricCard).update_value(
                    str(d.get("resource_skipped", 0)))
            except Exception:
                pass

            
            incidents = d.get("recent_incidents", [])
            if incidents:
                t = self.query_one("#dash-alerts-table", DataTable)
                t.clear()
                for inc in reversed(incidents[-8:]):
                    sev = inc.get("severity", "?")
                    badge = {"CRITICAL": "🔴", "HIGH": "🟠",
                             "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                    ts = time.strftime("%H:%M:%S",
                                       time.localtime(inc.get("timestamp", 0)))
                    src = inc.get("source", "?")[:9]
                    desc = inc.get("description", "")[:55]
                    t.add_row(badge, ts, sev[:6], src, desc)


    class NetworkTab(Static):
        def compose(self) -> ComposeResult:
            with Horizontal():
                with Vertical(id="net-left"):
                    yield Label("[bold #58A6FF]Active Connections[/bold #58A6FF]")
                    yield DataTable(id="net-conns-table")
                    yield Label("\n[bold #F0B429]Tracker Alerts[/bold #F0B429]")
                    yield DataTable(id="net-trackers-table")

                with Vertical(id="net-right"):
                    yield Label("[bold #3FB950]Top Domains (DNS)[/bold #3FB950]")
                    yield DataTable(id="net-domains-table")
                    yield Label("\n[bold #58A6FF]WiFi Devices[/bold #58A6FF]")
                    yield DataTable(id="net-wifi-table")

            yield Label("\n[bold #C9D1D9]Connection Tree[/bold #C9D1D9]")
            yield Static("", id="net-tree-view", classes="panel")


            with Horizontal():
                with Vertical():
                    yield Label("[bold #58A6FF]⚡ Internet Speed Test[/bold #58A6FF]")
                    yield Static("[dim]Press button to start[/dim]",
                                 id="net-speed-result", classes="panel")
                    with Horizontal():
                        yield Button("⚡ Speed Test",   id="btn-speedtest",       variant="primary")
                        yield Button("⚡ Quick",        id="btn-speedtest-quick", variant="default")
                        yield Button("📶 Ping Only",    id="btn-ping-only",       variant="default")
                        yield Button("📶 Scan WiFi Security", id="btn-wifi-scan", variant="primary")

                with Vertical():
                    yield Label("[bold #F0B429]🔒 VPN Leak Detector[/bold #F0B429]")
                    yield Static("[dim]Press button to check[/dim]",
                                 id="net-vpn-result", classes="panel")
                    yield Button("🔒 VPN Leak Test", id="btn-vpn-test", variant="warning")
                    


            
            yield Static("[dim]Press 'Scan WiFi Security' to detect nearby threats[/dim]", id="net-wifi-sec-summary", classes="panel")
            yield DataTable(id="net-wifi-sec-table")

        def on_mount(self):
            ct = self.query_one("#net-conns-table", DataTable)
            ct.add_columns("Process", "Remote Host", "Port", "Proto", "⚠")

            tt = self.query_one("#net-trackers-table", DataTable)
            tt.add_columns("Domain", "Tracker Name", "Count")

            dt = self.query_one("#net-domains-table", DataTable)
            dt.add_columns("Domain", "Requests", "Type")

            wt = self.query_one("#net-wifi-table", DataTable)
            wt.add_columns("IP", "Hostname/Vendor", "MAC")

            ws = self.query_one("#net-wifi-sec-table", DataTable)
            ws.add_columns("SSID", "Security", "WPS", "Band", "Risk", "Signal")
            

        def refresh_data(self, app_ref):
            d = app_ref.engine_data

            
            ct = self.query_one("#net-conns-table", DataTable)
            ct.clear()
            for c in d.get("connections", [])[:12]:
                flag = "⚠" if c.get("is_suspicious") or c.get("is_tracker") else ""
                ct.add_row(
                    c.get("process_name", "?")[:16],
                    (c.get("remote_hostname") or c.get("remote_ip", "?"))[:25],
                    str(c.get("remote_port", 0)),
                    c.get("protocol", "?")[:5],
                    flag,
                )

            
            tt = self.query_one("#net-trackers-table", DataTable)
            tt.clear()
            for t in d.get("tracker_domains", [])[:8]:
                tt.add_row(t.get("domain", "")[:28],
                           t.get("tracker_name", "")[:22],
                           str(t.get("count", 0)))

            
            dt = self.query_one("#net-domains-table", DataTable)
            dt.clear()
            for dom in d.get("top_domains", [])[:12]:
                dtype = "TRACKER" if dom.get("is_tracker") else "clean"
                dt.add_row(dom.get("domain", "")[:28],
                           str(dom.get("count", 0)), dtype)


            speed = d.get("speed_test_result")
            if speed:
                qc = speed.get("quality_color", "#C9D1D9")
                txt = (
                    f"[{qc}]{speed.get('quality','?')}[/{qc}]  "
                    f"↓ [{qc}]{speed.get('download_mbps',0):.1f} Mbps[/{qc}]  "
                    f"↑ {speed.get('upload_mbps',0):.1f} Mbps  "
                    f"Ping {speed.get('best_ping_ms',-1):.0f}ms  "
                    f"DNS {speed.get('dns_avg_ms',0):.0f}ms  "
                    f"IP: {speed.get('isp_ip','?')}"
                )
                try:
                    self.query_one("#net-speed-result", Static).update(txt)
                except Exception:
                    pass


            vpn = d.get("vpn_leak_result")
            if vpn:
                rc  = vpn.get("risk_color", "#C9D1D9")
                vpn_txt = (
                    f"[{rc}]{vpn.get('risk_level','?')}[/{rc}]  "
                    f"VPN: {'[green]Yes[/green]' if vpn.get('vpn_detected') else '[dim]No[/dim]'}  "
                    f"IP: {vpn.get('public_ip','?')}  "
                    f"DNS Leak: {'[red]YES[/red]' if vpn.get('dns_leak') else '[green]No[/green]'}  "
                    f"Split Tunnel: {'[yellow]Yes[/yellow]' if vpn.get('split_tunnel') else '[green]No[/green]'}"
                )
                try:
                    self.query_one("#net-vpn-result", Static).update(vpn_txt)
                except Exception:
                    pass


            wifi_scan = d.get("wifi_security_result")
            if wifi_scan:
                ws = self.query_one("#net-wifi-sec-table", DataTable)
                ws.clear()
                for net in wifi_scan.get("networks", [])[:10]:
                    sec = net.get("security","?")
                    sec_c = {"OPEN":"red","WEP":"red","WPA":"yellow",
                             "WPA2":"green","WPA3":"bold green"}.get(sec,"")
                    rc2   = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow",
                             "LOW":"cyan","SAFE":"green"}.get(net.get("risk","?"),"")
                    ws.add_row(
                        net.get("ssid","?")[:24] or "[dim](hidden)[/dim]",
                        f"[{sec_c}]{sec}[/{sec_c}]",
                        "[red]Yes[/red]" if net.get("wps") else "[dim]No[/dim]",
                        net.get("band","?"),
                        f"[{rc2}]{net.get('risk','?')}[/{rc2}]",
                        str(net.get("signal_dbm","?")),
                    )
                rc3 = wifi_scan.get("risk_color","#C9D1D9")
                summary = (
                    f"[{rc3}]{wifi_scan.get('risk_level','?')}[/{rc3}]  "
                    f"Open:[red]{wifi_scan.get('open',0)}[/red]  "
                    f"WEP:[red]{wifi_scan.get('wep',0)}[/red]  "
                    f"WPS:[yellow]{wifi_scan.get('wps',0)}[/yellow]  "
                    f"EvilTwin:[red]{wifi_scan.get('evil_twins',0)}[/red]  "
                    f"Total:{wifi_scan.get('total',0)}"
                )
                try:
                    self.query_one("#net-wifi-sec-summary", Static).update(summary)
                except Exception:
                    pass

            
            wt = self.query_one("#net-wifi-table", DataTable)
            wt.clear()
            for dev in d.get("wifi_devices", [])[:8]:
                wt.add_row(dev.get("ip", "?"),
                           dev.get("display_name", "?")[:22],
                           dev.get("mac", "—"))

            
            tree_text = d.get("connection_tree", "(no data yet)")
            self.query_one("#net-tree-view", Static).update(tree_text)



    class SecurityTab(Static):
        def compose(self) -> ComposeResult:
            with Horizontal(classes="metrics-row"):
                yield MetricCard("IDS Alerts",  "0", "#FF7B72", id="sec-mc-ids")
                yield MetricCard("Anomalies",   "0", "#F0B429", id="sec-mc-anom")
                yield MetricCard("ML Ready",    "No","#6E7681", id="sec-mc-ml")
                yield MetricCard("Rules",       "7", "#3FB950", id="sec-mc-rules")

            with Horizontal():
                with Vertical():
                    yield Label("[bold #FF7B72]IDS Alerts[/bold #FF7B72]")
                    yield DataTable(id="sec-ids-table")

                with Vertical():
                    yield Label("[bold #F0B429]AI Anomaly Detector[/bold #F0B429]")
                    yield DataTable(id="sec-anom-table")
                    yield Label("\n[bold #C9D1D9]AI Feature Window[/bold #C9D1D9]")
                    yield DataTable(id="sec-feat-table")


            yield Label("\n[bold #58A6FF]🔐 SSL/TLS Analyzer[/bold #58A6FF]")
            with Horizontal():
                with Vertical():
                    yield DataTable(id="sec-ssl-live-table")
                    with Horizontal():
                        yield Button("🔐 Live TLS Scan",   id="btn-ssl-live",  variant="primary")
                        yield Button("📦 Scan APK",         id="btn-ssl-apk",   variant="default")

                with Vertical():
                    yield Label("[bold #FF7B72]APK SSL Issues[/bold #FF7B72]")
                    yield DataTable(id="sec-ssl-apk-table")
                    yield Static("[dim]Run 'Scan APK' → enter APK path[/dim]",
                                 id="sec-ssl-apk-summary", classes="panel")

        def on_mount(self):
            ids_t = self.query_one("#sec-ids-table", DataTable)
            ids_t.add_columns("⚑", "Time", "Rule", "Category", "Description")

            anom_t = self.query_one("#sec-anom-table", DataTable)
            anom_t.add_columns("Severity", "Type", "Description")

            feat_t = self.query_one("#sec-feat-table", DataTable)
            feat_t.add_columns("Feature", "Value")

            ssl_live = self.query_one("#sec-ssl-live-table", DataTable)
            ssl_live.add_columns("Domain", "TLS", "Cipher", "Expires", "Risk")

            ssl_apk = self.query_one("#sec-ssl-apk-table", DataTable)
            ssl_apk.add_columns("Sev", "Location", "Description")

        def refresh_data(self, app_ref):
            d = app_ref.engine_data

            try:
                self.query_one("#sec-mc-ids", MetricCard).update_value(
                    str(d.get("ids_total", 0)),
                    "#FF7B72" if d.get("ids_total", 0) > 0 else "#3FB950")
            except Exception:
                pass
            try:
                self.query_one("#sec-mc-anom", MetricCard).update_value(
                    str(d.get("anomaly_total", 0)))
            except Exception:
                pass
            try:
                ready = d.get("anomaly_model_ready", False)
                self.query_one("#sec-mc-ml", MetricCard).update_value(
                    "Ready" if ready else "Warm-up",
                    "#3FB950" if ready else "#F0B429")
            except Exception:
                pass

            # IDS table
            ids_t = self.query_one("#sec-ids-table", DataTable)
            ids_t.clear()
            for a in d.get("ids_alerts", [])[-10:]:
                sev = a.get("severity", "?")
                badge = {"CRITICAL": "🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(sev,"⚪")
                ts = time.strftime("%H:%M:%S", time.localtime(a.get("timestamp", 0)))
                ids_t.add_row(badge, ts, a.get("rule_id","?"),
                              a.get("category","?")[:12],
                              a.get("description","")[:45])

            
            anom_t = self.query_one("#sec-anom-table", DataTable)
            anom_t.clear()
            for a in d.get("anomaly_alerts", [])[-8:]:
                anom_t.add_row(a.get("severity","?"),
                               a.get("alert_type","?")[:12],
                               a.get("description","")[:40])

            
            feat_t = self.query_one("#sec-feat-table", DataTable)
            feat_t.clear()
            for name, val in d.get("traffic_features", {}).items():
                feat_t.add_row(name, f"{val:.3f}")


            ssl_live_data = d.get("ssl_live_result", [])
            if ssl_live_data:
                ssl_live = self.query_one("#sec-ssl-live-table", DataTable)
                ssl_live.clear()
                for cert in ssl_live_data:
                    rc = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow",
                          "OK":"green","LOW":"cyan"}.get(cert.get("risk","?"),"")
                    exp = cert.get("days_remaining", 0)
                    exp_c = "[red]" if exp < 0 else "[yellow]" if exp < 30 else "[green]"
                    tls_c = "[red]" if cert.get("weak_tls") else "[green]"
                    ssl_live.add_row(
                        cert.get("domain","?")[:22],
                        f"{tls_c}{cert.get('tls_version','?')}[/{tls_c.strip('<')}]",
                        cert.get("cipher","?")[:24],
                        f"{exp_c}{exp}d[/{exp_c.strip('<')}]" if not cert.get("error") else "[dim]error[/dim]",
                        f"[{rc}]{cert.get('risk','?')}[/{rc}]",
                    )

            
            ssl_apk_data = d.get("ssl_apk_result", {})
            if ssl_apk_data:
                apk_t = self.query_one("#sec-ssl-apk-table", DataTable)
                apk_t.clear()
                for hit in ssl_apk_data.get("hits", [])[:10]:
                    sev = hit.get("severity","?")
                    sc = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"dim"}.get(sev,"")
                    apk_t.add_row(
                        f"[{sc}]{sev[:4]}[/{sc}]",
                        hit.get("location","?")[:10],
                        hit.get("description","?")[:50],
                    )
                risk = ssl_apk_data.get("risk_level","?")
                rc2  = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}.get(risk,"")
                try:
                    self.query_one("#sec-ssl-apk-summary", Static).update(
                        f"[bold]Package:[/bold] {ssl_apk_data.get('package','?')}  "
                        f"[bold]Risk:[/bold] [{rc2}]{risk}[/{rc2}]  "
                        f"Score:{ssl_apk_data.get('score',0)}  "
                        f"Critical:{ssl_apk_data.get('critical',0)}  "
                        f"High:{ssl_apk_data.get('high',0)}"
                    )
                except Exception:
                    pass

        def on_button_pressed(self, event: Button.Pressed):
            if event.button.id == "btn-ssl-live":
                self.app.trigger_ssl_live_scan()
            elif event.button.id == "btn-ssl-apk":
                self.app.trigger_ssl_apk_scan()

    

    class DefenseTab(Static):
        def compose(self) -> ComposeResult:
            with Horizontal(classes="metrics-row"):
                yield MetricCard("Mode",           "—",  "#F0B429", id="def-mc-mode")
                yield MetricCard("Blocked Domains","0",  "#FF7B72", id="def-mc-dom")
                yield MetricCard("Blocked IPs",    "0",  "#FF7B72", id="def-mc-ip")
                yield MetricCard("Flagged Apps",   "0",  "#D29922", id="def-mc-apps")

            with Horizontal():
                
                with Vertical():
                    yield Label("[bold #FF7B72]Blocked Domains[/bold #FF7B72]")
                    yield DataTable(id="def-block-table")

                    yield Label("\n[bold #C9D1D9]Policy Rules[/bold #C9D1D9]")
                    yield Static("", id="def-policy-view", classes="panel")

                
                with Vertical():
                    yield Label("[bold #F0B429]Recent Incidents[/bold #F0B429]")
                    yield DataTable(id="def-inc-table")

                    yield Label("\n[bold #3FB950]🧹 Debloat — Detected Bloatware[/bold #3FB950]")
                    yield DataTable(id="def-bloat-table")

            
            with Horizontal():
                yield Button("🛡  MONITOR",      id="btn-monitor",   variant="default")
                yield Button("⚔  DEFENSIVE",    id="btn-defensive", variant="warning")
                yield Button("🔒 STRICT",         id="btn-strict",    variant="error")
                yield Button("🧹 Scan Bloatware", id="btn-debloat",   variant="default")
                yield Button("🔧 Harden (SAFE)",  id="btn-harden",    variant="default")

        def on_mount(self):
            bt = self.query_one("#def-block-table", DataTable)
            bt.add_columns("Domain", "Threat", "Source")

            it = self.query_one("#def-inc-table", DataTable)
            it.add_columns("⚑", "Time", "Sev", "Description")

            bloat_t = self.query_one("#def-bloat-table", DataTable)
            bloat_t.add_columns("Package", "Description", "Disable Command")

        def refresh_data(self, app_ref):
            d = app_ref.engine_data

            mode = d.get("defense_mode", "MONITOR")
            mc = {"MONITOR": "#58A6FF", "DEFENSIVE": "#F0B429",
                  "STRICT": "#FF7B72"}.get(mode, "#C9D1D9")
            try:
                self.query_one("#def-mc-mode", MetricCard).update_value(mode, mc)
                self.query_one("#def-mc-dom", MetricCard).update_value(
                    str(d.get("blocked_domains", 0)))
                self.query_one("#def-mc-ip", MetricCard).update_value(
                    str(d.get("blocked_ips", 0)))
                self.query_one("#def-mc-apps", MetricCard).update_value(
                    str(d.get("flagged_apps_count", 0)))
            except Exception:
                pass

            
            bt = self.query_one("#def-block-table", DataTable)
            bt.clear()
            for e in d.get("blocklist", [])[:10]:
                bt.add_row(e.get("ioc","")[:28],
                           e.get("threat_type","")[:14],
                           e.get("source","")[:8])
            if not d.get("blocklist"):
                bt.add_row("[dim]none blocked yet[/dim]", "", "")

            
            rules = d.get("policy_rules", {})
            if rules:
                lines = []
                for k, v in rules.items():
                    icon  = "[#3FB950]●[/#3FB950]" if v else "[#6E7681]○[/#6E7681]"
                    state = "[#3FB950]ON[/#3FB950]" if v else "[#6E7681]off[/#6E7681]"
                    lines.append(f"  {icon} {k:<25} {state}")
                self.query_one("#def-policy-view", Static).update("\n".join(lines))
            else:
                self.query_one("#def-policy-view", Static).update(
                    "[dim]Policy engine initialising...[/dim]")

            
            it = self.query_one("#def-inc-table", DataTable)
            it.clear()
            for inc in reversed(d.get("recent_incidents", [])[-8:]):
                sev = inc.get("severity", "?")
                badge = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}.get(sev,"⚪")
                ts = time.strftime("%H:%M:%S",
                                   time.localtime(inc.get("timestamp", 0)))
                it.add_row(badge, ts, sev[:4],
                           inc.get("description","")[:48])
            if not d.get("recent_incidents"):
                it.add_row("⚪", "", "[green]CLEAN[/green]", "No incidents")


            bloat_t = self.query_one("#def-bloat-table", DataTable)
            bloat_t.clear()
            bloatware = d.get("bloatware_list", [])
            for pkg in bloatware[:8]:
                bloat_t.add_row(
                    pkg.get("package","")[:28],
                    pkg.get("description","")[:25],
                    f"pm disable-user --user 0 {pkg.get('package','')}"[:40],
                )
            if not bloatware:
                bloat_t.add_row("[dim]Press 'Scan Bloatware' to detect[/dim]", "", "")

        def on_button_pressed(self, event: Button.Pressed):
            btn_id = event.button.id
            mode_map = {
                "btn-monitor":   "MONITOR",
                "btn-defensive": "DEFENSIVE",
                "btn-strict":    "STRICT",
            }
            if btn_id in mode_map:
                self.app.set_defense_mode(mode_map[btn_id])
            elif btn_id == "btn-debloat":
                self.app.trigger_debloat_scan()
            elif btn_id == "btn-harden":
                self.app.trigger_hardening()

    

    class LabTab(Static):
        def compose(self) -> ComposeResult:
            with Horizontal():
                with Vertical():
                    yield Label("[bold #58A6FF]Network Graph[/bold #58A6FF]")
                    yield Static("", id="lab-graph-view", classes="panel")

                    yield Label("\n[bold #D29922]C2 / Beaconing Candidates[/bold #D29922]")
                    yield DataTable(id="lab-c2-table")

                with Vertical():
                    yield Label("[bold #F0B429]Threat Intel Cache[/bold #F0B429]")
                    yield DataTable(id="lab-intel-table")

                    yield Label("\n[bold #C9D1D9]App Behavior ML[/bold #C9D1D9]")
                    yield DataTable(id="lab-ml-table")

            with Horizontal():
                yield Button("🔄 Refresh Graph",  id="btn-graph",  variant="default")
                yield Button("🔍 APK Analysis",   id="btn-apk",    variant="default")
                yield Button("📡 IOC Update",      id="btn-ioc",    variant="default")
                yield Button("📊 Gen Report",      id="btn-report", variant="primary")

        def on_mount(self):
            c2t = self.query_one("#lab-c2-table", DataTable)
            c2t.add_columns("App", "Remote", "Interval", "Confidence")

            it = self.query_one("#lab-intel-table", DataTable)
            it.add_columns("IOC", "Reputation", "Score")

            mlt = self.query_one("#lab-ml-table", DataTable)
            mlt.add_columns("App", "Risk", "Prob", "Label")

        def refresh_data(self, app_ref):
            d = app_ref.engine_data

            
            self.query_one("#lab-graph-view", Static).update(
                d.get("connection_tree", "(collecting data...)"))

            
            c2t = self.query_one("#lab-c2-table", DataTable)
            c2t.clear()
            for c in d.get("c2_candidates", [])[:8]:
                c2t.add_row(
                    c.get("app", "?")[:18],
                    c.get("remote", "?")[:22],
                    f"{c.get('interval_mean', 0):.1f}s",
                    c.get("confidence", "?"),
                )


            it = self.query_one("#lab-intel-table", DataTable)
            it.clear()
            for e in d.get("malicious_iocs", [])[:10]:
                rep = e.get("reputation", "?")
                it.add_row(e.get("ioc","")[:25], rep, f"{e.get('score',0):.2f}")

            
            mlt = self.query_one("#lab-ml-table", DataTable)
            mlt.clear()
            for p in d.get("ml_predictions", [])[:8]:
                mlt.add_row(
                    p.get("package_name","?").split(".")[-1][:18],
                    p.get("risk_level","?"),
                    f"{p.get('probability_malware',0):.0%}",
                    p.get("risk_label","?"),
                )

        def on_button_pressed(self, event: Button.Pressed):
            btn_id = event.button.id
            if btn_id == "btn-graph":
                self.app.trigger_graph_rebuild()
            elif btn_id == "btn-report":
                self.app.trigger_report_generation()
            elif btn_id == "btn-ioc":
                self.app.trigger_ioc_update()

    

    class ReportTab(Static):
        def compose(self) -> ComposeResult:
            with Horizontal(classes="metrics-row"):
                yield MetricCard("Risk Level",    "LOW",  "#3FB950", id="rep-mc-risk")
                yield MetricCard("Risk Score",    "0",    "#58A6FF", id="rep-mc-score")
                yield MetricCard("Reports Saved", "0",    "#6E7681", id="rep-mc-count")
                yield MetricCard("Last Report",   "never","#6E7681", id="rep-mc-last")

            yield Label("[bold #C9D1D9]Security Report Preview[/bold #C9D1D9]")
            yield Static(
                "[dim]Press Generate Report to create a report[/dim]",
                id="rep-preview", classes="panel")

            yield Label("\n[bold #58A6FF]📁 Saved Reports[/bold #58A6FF]")
            yield DataTable(id="rep-saved-table")

            with Horizontal():
                yield Button("📋 Generate Report",   id="btn-gen-report", variant="primary")
                yield Button("💾 Save JSON",          id="btn-save-json",  variant="default")
                yield Button("📝 Save Markdown",      id="btn-save-md",    variant="default")
                yield Button("🗑  Delete Latest",     id="btn-del-report", variant="error")
                yield Button("🗑  Delete All",        id="btn-del-all",    variant="error")

        def on_mount(self):
            saved_t = self.query_one("#rep-saved-table", DataTable)
            saved_t.add_columns("ID", "Date", "Risk", "Score", "File")

        def refresh_data(self, app_ref):
            d = app_ref.engine_data
            risk = d.get("report_risk_level", "LOW")
            rc = {"CRITICAL": "#FF7B72","HIGH": "#F0B429",
                  "MEDIUM": "#D29922","LOW": "#3FB950"}.get(risk, "#3FB950")
            try:
                self.query_one("#rep-mc-risk", MetricCard).update_value(risk, rc)
                self.query_one("#rep-mc-score", MetricCard).update_value(
                    str(d.get("report_risk_score", 0)))
            except Exception:
                pass


            saved_reports = d.get("saved_reports_list", [])
            try:
                saved_t = self.query_one("#rep-saved-table", DataTable)
                saved_t.clear()
                for r in saved_reports[:10]:
                    rsk = r.get("risk_level","?")
                    rskc = {"CRITICAL":"bold red","HIGH":"red",
                            "MEDIUM":"yellow","LOW":"green"}.get(rsk,"")
                    saved_t.add_row(
                        r.get("id","?")[:16],
                        r.get("date","?")[:16],
                        f"[{rskc}]{rsk}[/{rskc}]",
                        str(r.get("risk_score","?")),
                        r.get("filename","?")[:30],
                    )
                self.query_one("#rep-mc-count", MetricCard).update_value(
                    str(len(saved_reports)))
                if saved_reports:
                    self.query_one("#rep-mc-last", MetricCard).update_value(
                        saved_reports[-1].get("date","?")[:10])
            except Exception:
                pass


            preview = d.get("report_preview_text", "")
            if preview:
                try:
                    self.query_one("#rep-preview", Static).update(preview)
                except Exception:
                    pass

        def on_button_pressed(self, event: Button.Pressed):
            btn_id = event.button.id
            if btn_id == "btn-gen-report":
                self.app.trigger_report_generation()
                try:
                    self.query_one("#rep-preview", Static).update(
                        "[#3FB950]Generating report — please wait...[/#3FB950]")
                except Exception:
                    pass
            elif btn_id == "btn-save-json":
                self.app.trigger_save_report("json")
            elif btn_id == "btn-save-md":
                self.app.trigger_save_report("md")
            elif btn_id == "btn-del-report":
                self.app.trigger_delete_report(latest_only=True)
            elif btn_id == "btn-del-all":
                self.app.trigger_delete_report(latest_only=False)



    class DSRPDashboard(App):
        

        CSS = DSRP_CSS
        TITLE = "DSRP — Device Security Research Platform"

        BINDINGS = [
            Binding("q",     "quit",          "Quit",    show=True),
            Binding("r",     "refresh",       "Refresh", show=True),
            Binding("1",     "tab_dash",      "Dashboard"),
            Binding("2",     "tab_network",   "Network"),
            Binding("3",     "tab_security",  "Security"),
            Binding("4",     "tab_defense",   "Defense"),
            Binding("5",     "tab_lab",       "Lab"),
            Binding("6",     "tab_report",    "Report"),
            Binding("s",     "run_scan",      "Scan"),
            Binding("w",     "scan_wifi",     "WiFi Scan"),
            Binding("ctrl+b","block_prompt",  "Block"),
            Binding("ctrl+r","gen_report",    "Report"),
            Binding("?",     "show_help",     "Help",    show=True),
        ]

        
        engine_data: dict = {}

        def __init__(self, core=None, **kwargs):
            super().__init__(**kwargs)
            self._core = core          
            self._refresh_timer = None
            self.engine_data = {
                "cpu": 0, "ram_mb": 0,
                "net_up": 0, "net_down": 0,
                "incidents_total": 0,
                "blocked_total": 0,
                "tracker_count": 0,
                "apps_scanned": 0,
                "connections": [],
                "tracker_domains": [],
                "top_domains": [],
                "wifi_devices": [],
                "connection_tree": "(collecting...)",
                "ids_alerts": [],
                "anomaly_alerts": [],
                "traffic_features": {},
                "anomaly_model_ready": False,
                "ids_total": 0,
                "anomaly_total": 0,
                "defense_mode": "MONITOR",
                "blocked_domains": 0,
                "blocked_ips": 0,
                "flagged_apps_count": 0,
                "blocklist": [],
                "hardened_packages": [],
                "recent_incidents": [],
                "policy_rules": {},
                "c2_candidates": [],
                "malicious_iocs": [],
                "ml_predictions": [],
                "report_risk_level": "LOW",
                "report_risk_score": 0,
            }

        def compose(self) -> ComposeResult:
            
            with Horizontal(id="header-bar"):
                yield Label(
                    "⚡ [bold #58A6FF]DSRP[/bold #58A6FF] "
                    "[#6E7681]Device Security Research Platform[/#6E7681]",
                    id="header-logo")
                yield Label("● MODE: [bold #F0B429]MONITOR[/bold #F0B429]",
                            id="header-mode")
                yield Label("[#3FB950]● RUNNING[/#3FB950]",
                            id="header-status")


            with Horizontal(id="body"):
                with Vertical(id="sidebar"):
                    yield Label("[bold #58A6FF] DSRP[/bold #58A6FF]\n")
                    yield Button("📊 Dashboard", id="nav-dash",     classes="nav-item active")
                    yield Button("🌐 Network",   id="nav-network",  classes="nav-item")
                    yield Button("🛡 Security",  id="nav-security", classes="nav-item")
                    yield Button("⚔  Defense",  id="nav-defense",  classes="nav-item")
                    yield Button("🔬 Lab",       id="nav-lab",      classes="nav-item")
                    yield Button("📋 Report",    id="nav-report",   classes="nav-item")
                    yield Static(
                        "\n[#6E7681]─────────────[/#6E7681]\n"
                        "[#6E7681]v1.1 Stage 5 ©&[/#6E7681]",
                        id="sidebar-stats")

                with TabbedContent(id="main-tabs", initial="tab-dash"):
                    with TabPane("📊 Dashboard", id="tab-dash"):
                        yield DashboardTab(id="wgt-dash")
                    with TabPane("🌐 Network", id="tab-network"):
                        yield NetworkTab(id="wgt-network")
                    with TabPane("🛡 Security", id="tab-security"):
                        yield SecurityTab(id="wgt-security")
                    with TabPane("⚔ Defense", id="tab-defense"):
                        yield DefenseTab(id="wgt-defense")
                    with TabPane("🔬 Lab", id="tab-lab"):
                        yield LabTab(id="wgt-lab")
                    with TabPane("📋 Report", id="tab-report"):
                        yield ReportTab(id="wgt-report")

            yield Footer()

        def on_mount(self):
            
            self._refresh_timer = self.set_interval(3, self._tick)
            
            if self._core:
                threading.Thread(target=self._core.start_all,
                                 daemon=True).start()

        def _tick(self):
            
            if self._core:
                self.engine_data = self._core.collect_data()
            else:
                self._fill_demo_data()


            try:
                mode = self.engine_data.get("defense_mode", "MONITOR")
                mc = {"MONITOR":"#58A6FF","DEFENSIVE":"#F0B429",
                      "STRICT":"#FF7B72"}.get(mode, "#C9D1D9")
                self.query_one("#header-mode", Label).update(
                    f"● MODE: [bold {mc}]{mode}[/bold {mc}]")
            except Exception:
                pass


            try:
                tc = self.query_one("#main-tabs", TabbedContent)
                active = tc.active
                tab_widget_map = {
                    "tab-dash":     "#wgt-dash",
                    "tab-network":  "#wgt-network",
                    "tab-security": "#wgt-security",
                    "tab-defense":  "#wgt-defense",
                    "tab-lab":      "#wgt-lab",
                    "tab-report":   "#wgt-report",
                }
                widget_id = tab_widget_map.get(active)
                if widget_id:
                    w = self.query_one(widget_id)
                    if hasattr(w, "refresh_data"):
                        w.refresh_data(self)
            except Exception:
                pass

        def _fill_demo_data(self):
            
            import psutil
            import random
            self.engine_data.update({
                "cpu": psutil.cpu_percent(interval=None),
                "ram_mb": psutil.virtual_memory().used / 1024 / 1024,
                "defense_mode": "MONITOR",
                "connection_tree":
                    "Android Device\n"
                    " ├─ [APP] chrome\n"
                    " │   ├─ google.com:443\n"
                    " │   └─ googleapis.com:443\n"
                    " └─ [APP] com.example\n"
                    "     ├─ api.mixpanel.com:443 ⚠ TRACKER\n"
                    "     └─ graph.facebook.com:443 ⚠ TRACKER",
            })



        def action_quit(self):
            if self._core:
                self._core.stop_all()
            self.exit()

        def action_refresh(self):
            self._tick()

        def action_tab_dash(self):
            self._switch_tab("tab-dash")

        def action_tab_network(self):
            self._switch_tab("tab-network")

        def action_tab_security(self):
            self._switch_tab("tab-security")

        def action_tab_defense(self):
            self._switch_tab("tab-defense")

        def action_tab_lab(self):
            self._switch_tab("tab-lab")

        def action_tab_report(self):
            self._switch_tab("tab-report")

        def action_run_scan(self):
            if self._core:
                threading.Thread(target=self._core.run_app_scan,
                                 daemon=True).start()

        def action_scan_wifi(self):
            if self._core:
                threading.Thread(target=self._core.run_wifi_scan,
                                 daemon=True).start()

        def action_gen_report(self):
            self.trigger_report_generation()

        def action_show_help(self):
            help_text = (
                "DSRP Dashboard Shortcuts\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "1–6   Switch tabs\n"
                "r     Refresh data\n"
                "s     App malware scan\n"
                "w     WiFi scan\n"
                "Ctrl+B  Block a domain/IP\n"
                "Ctrl+R  Generate report\n"
                "q     Quit\n"
            )
            self.notify(help_text, title="Help", timeout=8)

        def _switch_tab(self, tab_id: str):
            try:
                tc = self.query_one("#main-tabs", TabbedContent)
                tc.active = tab_id
            except Exception:
                pass

        def set_defense_mode(self, mode: str):
            if self._core:
                self._core.set_mode(mode)
            self.engine_data["defense_mode"] = mode
            self.notify(f"Defense mode set to {mode}", timeout=3)

        def trigger_graph_rebuild(self):
            if self._core:
                threading.Thread(target=self._core.rebuild_graph,
                                 daemon=True).start()
            self.notify("Rebuilding network graph...", timeout=2)

        def trigger_report_generation(self):
            if self._core:
                threading.Thread(target=self._core.generate_report,
                                 daemon=True).start()
            self.notify("Generating security report...", timeout=3)

        def trigger_ioc_update(self):
            if self._core:
                threading.Thread(target=self._core.update_ioc_feeds,
                                 daemon=True).start()
            self.notify("Updating IOC feeds...", timeout=3)

        def trigger_debloat_scan(self):
            if self._core:
                threading.Thread(target=self._core.run_debloat_scan,
                                 daemon=True).start()
            self.notify("Scanning for bloatware...", timeout=3)

        def trigger_hardening(self, level: str = "SAFE"):
            if self._core:
                # Always dry_run=True from dashboard for safety
                threading.Thread(
                    target=self._core.run_hardening,
                    args=(level, True),
                    daemon=True,
                ).start()
            self.notify(
                f"Hardening preview ({level}) — check terminal for results",
                timeout=5)

        def trigger_speed_test(self, run_upload: bool = True, ping_only: bool = False):
            def _run():
                try:
                    from network.speed_test import SpeedTest
                    st = SpeedTest()
                    if ping_only:
                        pings = st.run_ping()
                        reachable = [p.latency_ms for p in pings if p.reachable]
                        best = min(reachable) if reachable else -1
                        self.engine_data["speed_test_result"] = {
                            "quality": "Ping only", "quality_color": "#58A6FF",
                            "download_mbps": 0, "upload_mbps": 0,
                            "best_ping_ms": best, "avg_ping_ms": sum(reachable)/max(len(reachable),1),
                            "dns_avg_ms": 0, "isp_ip": st._get_public_ip(),
                        }
                    else:
                        result = st.run(run_upload=run_upload)
                        self.engine_data["speed_test_result"] = {
                            "quality": result.quality, "quality_color": result.quality_color,
                            "download_mbps": result.download_mbps, "upload_mbps": result.upload_mbps,
                            "best_ping_ms": result.best_ping_ms, "avg_ping_ms": result.avg_ping_ms,
                            "dns_avg_ms": result.dns_avg_ms, "isp_ip": result.isp_ip,
                        }
                    dl = self.engine_data["speed_test_result"]["download_mbps"]
                    self.notify(f"Speed test done — ↓ {dl:.1f} Mbps", timeout=5)
                except Exception as e:
                    self.notify(f"Speed test failed: {e}", severity="error")
            self.notify("Running speed test...", timeout=3)
            threading.Thread(target=_run, daemon=True, name="speed-test").start()

        def list_saved_reports(self) -> list:
            if self._core:
                return self._core.list_reports()
            return []



        def trigger_vpn_leak_test(self):
            def _run():
                try:
                    from network.vpn_leak_detector import VPNLeakDetector
                    d = VPNLeakDetector()
                    report = d.run()
                    self.engine_data["vpn_leak_result"] = {
                        "risk_level":   report.risk_level,
                        "risk_color":   report.risk_color,
                        "vpn_detected": report.vpn_detected,
                        "public_ip":    report.public_ip_current,
                        "dns_leak":     report.dns_leak_detected,
                        "split_tunnel": report.split_tunnel_detected,
                        "findings":     report.findings[:5],
                        "recommendations": report.recommendations[:3],
                    }
                    self.notify(
                        f"VPN Leak Test done — {report.risk_level}"
                        + (" ⚠ LEAK!" if report.leak_detected else " ✓ Clean"),
                        timeout=5)
                except Exception as e:
                    self.notify(f"VPN test failed: {e}", severity="error")
            self.notify("Running VPN leak test...", timeout=3)
            threading.Thread(target=_run, daemon=True, name="vpn-test").start()

        def trigger_wifi_security_scan(self):
            def _run():
                try:
                    from network.wifi_security_checker import WiFiSecurityChecker
                    checker = WiFiSecurityChecker()
                    report  = checker.scan()
                    self.engine_data["wifi_security_result"] = {
                        "risk_level": report.risk_level,
                        "risk_color": report.risk_color,
                        "total":      report.total_networks,
                        "open":       len(report.open_networks),
                        "wep":        len(report.wep_networks),
                        "wps":        len(report.wps_networks),
                        "evil_twins": len(report.evil_twin_candidates),
                        "findings":   report.findings[:5],
                        "networks": [
                            {
                                "ssid":       n.ssid,
                                "security":   n.security,
                                "wps":        n.wps_enabled,
                                "band":       n.band,
                                "risk":       n.risk_level,
                                "signal_dbm": n.signal_dbm,
                                "connected":  n.is_connected,
                            }
                            for n in report.networks[:15]
                        ],
                    }
                    self.notify(
                        f"WiFi Scan done — {report.total_networks} networks, "
                        f"risk: {report.risk_level}", timeout=5)
                except Exception as e:
                    self.notify(f"WiFi scan failed: {e}", severity="error")
            self.notify("Scanning WiFi security...", timeout=3)
            threading.Thread(target=_run, daemon=True, name="wifi-scan").start()

        def trigger_ssl_live_scan(self, domains: list = None):
            def _run():
                try:
                    from network.ssl_tls_analyzer import SSLTLSAnalyzer
                    analyzer = SSLTLSAnalyzer()
                    report   = analyzer.scan_live_connections(domains)
                    self.engine_data["ssl_live_result"] = [
                        {
                            "domain":        c.domain,
                            "tls_version":   c.tls_version,
                            "cipher":        c.cipher_suite,
                            "days_remaining":c.days_remaining,
                            "is_expired":    c.is_expired,
                            "weak_tls":      c.has_weak_tls,
                            "risk":          c.risk,
                            "error":         c.error,
                        }
                        for c in report.certificates
                    ]
                    self.notify(
                        f"SSL scan done — {len(report.certificates)} domains, "
                        f"risk: {report.risk_level}", timeout=5)
                except Exception as e:
                    self.notify(f"SSL scan failed: {e}", severity="error")
            self.notify("Scanning SSL/TLS connections...", timeout=3)
            threading.Thread(target=_run, daemon=True, name="ssl-live").start()

        def trigger_save_report(self, fmt: str = "json"):
            """Save the last generated report in the given format."""
            if self._core and self._core.report_gen:
                try:
                    last = getattr(self._core.report_gen, "_last_report", None)
                    if last:
                        saved = self._core.report_gen.save(last, formats=[fmt])
                        self.notify(f"Saved {fmt.upper()} report", timeout=3)
                        self._refresh_saved_reports()
                    else:
                        self.notify("Generate a report first", severity="warning")
                except Exception as e:
                    self.notify(f"Save failed: {e}", severity="error")
            else:
                self.notify("Report engine not ready", severity="warning")

        def trigger_delete_report(self, latest_only: bool = True):
            
            if self._core and self._core.report_gen:
                try:
                    deleted = self._core.report_gen.delete_reports(
                        latest_only=latest_only)
                    label = "latest report" if latest_only else "all reports"
                    self.notify(f"Deleted {deleted} {label}", timeout=3)
                    self._refresh_saved_reports()
                except Exception as e:
                    self.notify(f"Delete failed: {e}", severity="error")
            else:
                
                import os, glob
                from pathlib import Path
                rdir = Path(__file__).parent.parent / "data" / "reports"
                if rdir.exists():
                    files = sorted(rdir.glob("*.json"))
                    if latest_only and files:
                        files[-1].unlink(missing_ok=True)
                        self.notify("Deleted latest report", timeout=3)
                    elif not latest_only:
                        for f in rdir.glob("report_*"):
                            f.unlink(missing_ok=True)
                        self.notify(f"Deleted all reports", timeout=3)
                self._refresh_saved_reports()

        def _refresh_saved_reports(self):

            try:
                import os, json
                from pathlib import Path
                rdir = Path(__file__).parent.parent / "data" / "reports"
                reports = []
                if rdir.exists():
                    for f in sorted(rdir.glob("report_*.json"),
                                    key=lambda x: x.stat().st_mtime):
                        try:
                            with open(f) as fp:
                                meta = json.load(fp)
                            reports.append({
                                "id":         meta.get("report_id", f.stem)[:16],
                                "date":       meta.get("generated_at", "?")[:16],
                                "risk_level": meta.get("risk_level", "?"),
                                "risk_score": meta.get("risk_score", 0),
                                "filename":   f.name[:30],
                            })
                        except Exception:
                            reports.append({
                                "id": f.stem[:16], "date": "?",
                                "risk_level": "?", "risk_score": 0,
                                "filename": f.name[:30],
                            })
                self.engine_data["saved_reports_list"] = list(reversed(reports))
            except Exception:
                pass

        def trigger_report_generation(self):
            
            def _run():
                if self._core:
                    self._core.generate_report()

                d = self.engine_data
                lines = [
                    f"[bold #58A6FF]DSRP Security Report[/bold #58A6FF]",
                    f"[dim]Generated: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
                    "",
                    f"[bold]Risk Level  :[/bold] {d.get('report_risk_level','LOW')}",
                    f"[bold]Risk Score  :[/bold] {d.get('report_risk_score',0)}",
                    f"[bold]Incidents   :[/bold] {d.get('incidents_total',0)}",
                    f"[bold]Blocked     :[/bold] {d.get('blocked_total',0)}",
                    f"[bold]Trackers    :[/bold] {d.get('tracker_count',0)}",
                    f"[bold]IDS Alerts  :[/bold] {d.get('ids_total',0)}",
                    f"[bold]Anomalies   :[/bold] {d.get('anomaly_total',0)}",
                    f"[bold]Apps Scanned:[/bold] {d.get('apps_scanned',0)}",
                    "",
                ]
                if d.get("recent_incidents"):
                    lines.append("[bold #FF7B72]Recent Incidents:[/bold #FF7B72]")
                    for inc in d["recent_incidents"][-5:]:
                        sev = inc.get("severity","?")
                        lines.append(f"  • [{sev}] {inc.get('description','')[:60]}")
                self.engine_data["report_preview_text"] = "\n".join(lines)
                self._refresh_saved_reports()
                self.notify("Report generated", timeout=3)

            threading.Thread(target=_run, daemon=True,
                             name="report-gen").start()

        def trigger_ssl_apk_scan(self, apk_path: str = ""):
            def _run(path):
                try:
                    from network.ssl_tls_analyzer import SSLTLSAnalyzer
                    analyzer = SSLTLSAnalyzer()
                    report   = analyzer.scan_apk(path)
                    if report.error:
                        self.notify(f"APK scan error: {report.error}",
                                    severity="error")
                        return
                    self.engine_data["ssl_apk_result"] = {
                        "package":  report.package_name,
                        "risk_level": report.risk_level,
                        "score":    report.risk_score,
                        "critical": report.critical_count,
                        "high":     report.high_count,
                        "hits": [
                            {
                                "severity":    h.severity,
                                "location":    h.location,
                                "description": h.description,
                            }
                            for h in report.bypass_hits[:15]
                        ],
                    }
                    self.notify(
                        f"APK SSL scan done — {report.package_name} — "
                        f"risk: {report.risk_level}", timeout=6)
                except Exception as e:
                    self.notify(f"APK SSL scan failed: {e}", severity="error")

            if not apk_path:

                self.notify(
                    "Enter APK path in terminal: python dsrp.py ssl /path/to.apk",
                    timeout=6)
                return
            threading.Thread(target=_run, args=(apk_path,),
                             daemon=True, name="ssl-apk").start()

        def on_button_pressed(self, event: Button.Pressed):
            nav_map = {
                "nav-dash":     "tab-dash",
                "nav-network":  "tab-network",
                "nav-security": "tab-security",
                "nav-defense":  "tab-defense",
                "nav-lab":      "tab-lab",
                "nav-report":   "tab-report",
            }
            if event.button.id in nav_map:
                self._switch_tab(nav_map[event.button.id])
            elif event.button.id == "btn-speedtest":
                self.trigger_speed_test(run_upload=True)
            elif event.button.id == "btn-speedtest-quick":
                self.trigger_speed_test(run_upload=False)
            elif event.button.id == "btn-ping-only":
                self.trigger_speed_test(ping_only=True)
            elif event.button.id == "btn-vpn-test":
                self.trigger_vpn_leak_test()
            elif event.button.id == "btn-wifi-scan":
                self.trigger_wifi_security_scan()
            elif event.button.id == "btn-ssl-live":
                self.trigger_ssl_live_scan()
            elif event.button.id == "btn-ssl-apk":
                self.trigger_ssl_apk_scan()



def _fmt_rate(bps: float) -> str:
    if bps >= 1_000_000:
        return f"{bps/1_000_000:.1f}M/s"
    elif bps >= 1_000:
        return f"{bps/1_000:.0f}K/s"
    return f"{bps:.0f}B/s"
