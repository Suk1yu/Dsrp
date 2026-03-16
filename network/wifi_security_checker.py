"""
network/wifi_security_checker.py

WiFi Security Checker — Cross-Platform (Android / Linux / Windows)

Detects:
  - Open networks (no encryption)
  - WEP encryption (deprecated, crackable in minutes)
  - WPS enabled (brute-force vulnerable)
  - Weak passwords indicators (SSID = password patterns)
  - Evil twin / rogue AP detection (same SSID, different BSSID)
  - Hidden SSIDs
  - Connected network security
  - 2.4GHz vs 5GHz (2.4GHz more susceptible to some attacks)

Scan methods (no root needed):
  Android:  iw / iwlist / wpa_cli + /proc/net/wireless
  Linux:    nmcli / iwlist / iw
  Windows:  netsh wlan
"""

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Security ratings
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_RISK = {
    "OPEN":   ("CRITICAL", "No encryption — all traffic visible to anyone nearby"),
    "WEP":    ("CRITICAL", "WEP is broken — crackable in under 5 minutes"),
    "WPS":    ("HIGH",     "WPS PIN attack — brute-forceable in hours"),
    "WPA":    ("MEDIUM",   "WPA (TKIP) has known vulnerabilities"),
    "WPA2":   ("LOW",      "WPA2 is generally secure with strong password"),
    "WPA3":   ("SAFE",     "WPA3 — current strongest standard"),
    "UNKNOWN":("MEDIUM",   "Cannot determine security type"),
}

# Patterns that suggest default/weak router credentials
WEAK_SSID_PATTERNS = [
    r"^(NETGEAR|Linksys|TP-Link|Dlink|D-Link|Belkin|ASUS|Xiaomi|HUAWEI|"
    r"TPLINK|Tenda|Archer|xFi|XFINITY|Spectrum|ATT|Verizon|Cox|Comcast|"
    r"BTHub|SKY|TALKTALK|BT-)[_\-\s]?\d{3,}$",
    r"default",
    r"^router$",
    r"^wifi$",
    r"^home$",
    r"^admin$",
]


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str = ""
    signal_dbm: int = 0
    channel: int = 0
    frequency_ghz: float = 0.0
    security: str = "UNKNOWN"    # OPEN / WEP / WPA / WPA2 / WPA3
    wps_enabled: bool = False
    is_hidden: bool = False
    is_connected: bool = False
    vendor: str = ""

    @property
    def band(self) -> str:
        if self.frequency_ghz >= 5.0:
            return "5GHz"
        elif self.frequency_ghz >= 2.4:
            return "2.4GHz"
        elif self.channel > 14:
            return "5GHz"
        elif self.channel > 0:
            return "2.4GHz"
        return "?"

    @property
    def risk_level(self) -> str:
        if self.security in ("OPEN", "WEP"):
            return "CRITICAL"
        if self.wps_enabled:
            return "HIGH"
        if self.security in ("WPA",):
            return "MEDIUM"
        if self.security == "WPA2":
            return "LOW"
        if self.security == "WPA3":
            return "SAFE"
        return "MEDIUM"

    @property
    def risk_color(self) -> str:
        return {
            "CRITICAL": "bold red", "HIGH": "red",
            "MEDIUM": "yellow",     "LOW":  "cyan",
            "SAFE":   "green",      "MEDIUM": "yellow",
        }.get(self.risk_level, "white")


@dataclass
class EvilTwinCandidate:
    ssid: str
    legitimate_bssid: str
    suspicious_bssid: str
    legitimate_signal: int = 0
    suspicious_signal: int = 0
    reason: str = ""


@dataclass
class WiFiSecurityReport:
    timestamp: float = field(default_factory=time.time)
    platform: str = ""
    scan_duration_secs: float = 0.0

    # Networks
    networks: list = field(default_factory=list)
    connected_network: Optional[WiFiNetwork] = None

    # Issues
    open_networks: list = field(default_factory=list)
    wep_networks: list = field(default_factory=list)
    wps_networks: list = field(default_factory=list)
    evil_twin_candidates: list = field(default_factory=list)
    weak_ssid_networks: list = field(default_factory=list)

    # Summary
    total_networks: int = 0
    critical_count: int = 0
    high_count: int = 0
    risk_level: str = "LOW"
    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    error: str = ""

    @property
    def risk_color(self) -> str:
        return {
            "CRITICAL": "bold red", "HIGH": "red",
            "MEDIUM": "yellow",     "LOW":  "cyan",
            "SAFE":   "green",
        }.get(self.risk_level, "white")


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class WiFiSecurityChecker:
    """
    WiFi security scanner.
    Detects dangerous networks nearby and audits the connected network.
    """

    def __init__(self, progress_callback=None):
        self._progress = progress_callback
        self._platform = self._detect_platform()

    def scan(self) -> WiFiSecurityReport:
        """Full WiFi security scan. Returns WiFiSecurityReport."""
        report = WiFiSecurityReport(platform=self._platform)
        t0 = time.time()

        self._emit(10, "Scanning WiFi networks...")
        networks = self._scan_networks()
        report.networks      = networks
        report.total_networks = len(networks)

        self._emit(50, "Checking connected network...")
        connected = self._get_connected_network(networks)
        report.connected_network = connected

        self._emit(65, "Checking for security issues...")
        self._analyse_networks(report)

        self._emit(85, "Detecting evil twins...")
        self._detect_evil_twins(report)

        self._emit(95, "Assessing risk...")
        self._assess_risk(report)

        report.scan_duration_secs = round(time.time() - t0, 1)
        self._emit(100, "Done")
        return report

    # ── Network scanning ──────────────────────────────────────────────────────

    def _scan_networks(self) -> list[WiFiNetwork]:
        if self._platform == "android":
            return self._scan_android()
        elif self._platform == "linux":
            return self._scan_linux()
        elif self._platform == "windows":
            return self._scan_windows()
        return []

    def _scan_android(self) -> list[WiFiNetwork]:
        networks = []

        # Method 1: iw scan (if available)
        iw_out = self._run("iw dev 2>/dev/null | grep Interface | head -1")
        iface  = iw_out.replace("Interface", "").strip()
        if iface:
            out = self._run(f"iw {iface} scan 2>/dev/null")
            if out:
                networks = self._parse_iw_output(out)

        # Method 2: wpa_cli scan_results
        if not networks:
            self._run("wpa_cli -i wlan0 scan 2>/dev/null")
            time.sleep(1.5)
            out = self._run("wpa_cli -i wlan0 scan_results 2>/dev/null")
            if out:
                networks = self._parse_wpa_cli(out)

        # Method 3: /proc/net/wireless (fallback — connected only)
        if not networks:
            networks = self._parse_proc_wireless()

        return networks

    def _scan_linux(self) -> list[WiFiNetwork]:
        networks = []

        # Try nmcli first (most reliable)
        out = self._run(
            "nmcli -t -f SSID,BSSID,SIGNAL,SECURITY,FREQ,MODE device wifi list 2>/dev/null")
        if out and "SSID" not in out[:20]:
            networks = self._parse_nmcli(out)

        # Fallback: iwlist
        if not networks:
            iface = self._get_wifi_interface_linux()
            if iface:
                out = self._run(f"sudo iwlist {iface} scan 2>/dev/null || "
                                f"iwlist {iface} scan 2>/dev/null")
                if out:
                    networks = self._parse_iwlist(out)

        return networks

    def _scan_windows(self) -> list[WiFiNetwork]:
        out = self._run("netsh wlan show networks mode=Bssid 2>NUL")
        if out:
            return self._parse_netsh(out)
        return []

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_nmcli(self, output: str) -> list[WiFiNetwork]:
        networks = []
        for line in output.splitlines():
            parts = line.split(":")
            if len(parts) < 5:
                continue
            try:
                ssid     = parts[0].replace("\\:", ":")
                bssid    = parts[1].replace("\\:", ":").upper()
                signal   = int(parts[2]) if parts[2].isdigit() else 0
                security = parts[3].upper()
                freq_str = parts[4]

                freq = 0.0
                m = re.search(r"(\d+)", freq_str)
                if m:
                    mhz = int(m.group(1))
                    freq = mhz / 1000.0 if mhz > 100 else float(mhz)

                security_clean = self._clean_security(security)
                wps = "WPS" in security.upper()

                networks.append(WiFiNetwork(
                    ssid=ssid, bssid=bssid,
                    signal_dbm=signal - 110,  # nmcli gives 0-100
                    frequency_ghz=freq,
                    security=security_clean,
                    wps_enabled=wps,
                    is_hidden=(not ssid),
                ))
            except Exception:
                continue
        return networks

    def _parse_iwlist(self, output: str) -> list[WiFiNetwork]:
        networks = []
        current = None

        for line in output.splitlines():
            line = line.strip()

            if "Cell" in line and "Address:" in line:
                if current:
                    networks.append(current)
                m = re.search(r"Address:\s+([0-9A-F:]+)", line, re.I)
                bssid = m.group(1).upper() if m else ""
                current = WiFiNetwork(ssid="", bssid=bssid)

            elif current:
                m = re.search(r'ESSID:"([^"]*)"', line)
                if m:
                    current.ssid = m.group(1)

                m = re.search(r"Frequency:(\S+)\s+GHz", line)
                if m:
                    try:
                        current.frequency_ghz = float(m.group(1))
                    except Exception:
                        pass

                m = re.search(r"Signal level=(-?\d+)", line)
                if m:
                    current.signal_dbm = int(m.group(1))

                if "Encryption key:on" in line:
                    if current.security == "UNKNOWN":
                        current.security = "WEP"
                elif "Encryption key:off" in line:
                    current.security = "OPEN"

                if "WPA2" in line.upper():
                    current.security = "WPA2"
                elif "WPA3" in line.upper():
                    current.security = "WPA3"
                elif "WPA" in line.upper() and current.security not in ("WPA2", "WPA3"):
                    current.security = "WPA"

                if "WPS" in line:
                    current.wps_enabled = True

                m = re.search(r"Channel:(\d+)", line)
                if m:
                    current.channel = int(m.group(1))

        if current:
            networks.append(current)
        return networks

    def _parse_netsh(self, output: str) -> list[WiFiNetwork]:
        networks = []
        current  = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current:
                    networks.append(current)
                    current = None
                continue

            m = re.match(r"SSID\s+\d+\s*:\s+(.+)", line)
            if m:
                current = WiFiNetwork(ssid=m.group(1).strip())
                continue

            if not current:
                continue

            m = re.match(r"BSSID\s+\d+\s*:\s+([0-9a-fA-F:]+)", line)
            if m:
                current.bssid = m.group(1).upper()

            m = re.match(r"Authentication\s*:\s+(.+)", line, re.I)
            if m:
                auth = m.group(1).strip().upper()
                current.security = self._clean_security(auth)

            m = re.match(r"Signal\s*:\s+(\d+)%", line, re.I)
            if m:
                pct = int(m.group(1))
                current.signal_dbm = int(pct / 2) - 100

            m = re.match(r"Channel\s*:\s+(\d+)", line, re.I)
            if m:
                current.channel = int(m.group(1))
                current.frequency_ghz = 5.0 if current.channel > 14 else 2.4

        if current:
            networks.append(current)
        return networks

    def _parse_wpa_cli(self, output: str) -> list[WiFiNetwork]:
        networks = []
        for line in output.splitlines()[1:]:   # skip header
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            try:
                bssid = parts[0].strip().upper()
                freq  = int(parts[1].strip())
                sig   = int(parts[2].strip())
                flags = parts[3].strip().upper()
                ssid  = parts[4].strip() if len(parts) > 4 else ""

                security = self._flags_to_security(flags)
                wps      = "WPS" in flags

                networks.append(WiFiNetwork(
                    ssid=ssid, bssid=bssid,
                    signal_dbm=sig,
                    frequency_ghz=freq / 1000.0,
                    security=security,
                    wps_enabled=wps,
                    is_hidden=(not ssid),
                ))
            except Exception:
                continue
        return networks

    def _parse_iw_output(self, output: str) -> list[WiFiNetwork]:
        networks = []
        current  = None

        for line in output.splitlines():
            if line.startswith("BSS "):
                if current:
                    networks.append(current)
                m = re.match(r"BSS ([0-9a-f:]+)", line, re.I)
                current = WiFiNetwork(ssid="",
                                      bssid=m.group(1).upper() if m else "")
            elif current:
                m = re.search(r"SSID:\s*(.+)", line)
                if m:
                    current.ssid = m.group(1).strip()
                m = re.search(r"freq:\s*(\d+)", line)
                if m:
                    current.frequency_ghz = int(m.group(1)) / 1000.0
                m = re.search(r"signal:\s*([-\d.]+)", line)
                if m:
                    current.signal_dbm = int(float(m.group(1)))
                if "WPA3" in line:
                    current.security = "WPA3"
                elif "WPA2" in line:
                    current.security = "WPA2"
                elif "WPA" in line and current.security not in ("WPA2","WPA3"):
                    current.security = "WPA"
                if "Privacy" in line and current.security == "UNKNOWN":
                    current.security = "WEP"
                elif "ESS" in line and "Privacy" not in output[:100]:
                    if current.security == "UNKNOWN":
                        current.security = "OPEN"
                if "WPS" in line:
                    current.wps_enabled = True

        if current:
            networks.append(current)
        return networks

    def _parse_proc_wireless(self) -> list[WiFiNetwork]:
        """Fallback: read /proc/net/wireless for connected interface info."""
        networks = []
        try:
            with open("/proc/net/wireless") as f:
                for line in f.readlines()[2:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        iface  = parts[0].rstrip(":")
                        sig    = int(float(parts[3].rstrip(".")))
                        networks.append(WiFiNetwork(
                            ssid=f"(connected on {iface})",
                            signal_dbm=sig - 256 if sig > 0 else sig,
                            is_connected=True,
                            security="UNKNOWN",
                        ))
        except Exception:
            pass
        return networks

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _analyse_networks(self, report: WiFiSecurityReport):
        for net in report.networks:
            if net.security == "OPEN":
                report.open_networks.append(net)
                report.findings.append(
                    f"Open network: '{net.ssid or 'hidden'}' — unencrypted!")
            elif net.security == "WEP":
                report.wep_networks.append(net)
                report.findings.append(
                    f"WEP network: '{net.ssid}' — crackable in minutes!")
            if net.wps_enabled:
                report.wps_networks.append(net)
                report.findings.append(
                    f"WPS enabled: '{net.ssid}' — vulnerable to brute force")
            # Weak SSID patterns
            for pattern in WEAK_SSID_PATTERNS:
                if re.search(pattern, net.ssid, re.I):
                    report.weak_ssid_networks.append(net)
                    report.findings.append(
                        f"'{net.ssid}' looks like a default router name "
                        f"— likely default password")
                    break

    def _detect_evil_twins(self, report: WiFiSecurityReport):
        ssid_groups: dict = {}
        for net in report.networks:
            if not net.ssid:
                continue
            ssid_groups.setdefault(net.ssid, []).append(net)

        for ssid, nets in ssid_groups.items():
            if len(nets) < 2:
                continue
            # Same SSID, different BSSID — could be legitimate (multi-AP)
            # or evil twin. Flag if security types differ OR signal very different
            securities = {n.security for n in nets}
            if len(securities) > 1:
                # Different security types with same SSID = suspicious
                sorted_nets = sorted(nets, key=lambda n: n.signal_dbm,
                                     reverse=True)
                report.evil_twin_candidates.append(EvilTwinCandidate(
                    ssid=ssid,
                    legitimate_bssid=sorted_nets[0].bssid,
                    suspicious_bssid=sorted_nets[-1].bssid,
                    legitimate_signal=sorted_nets[0].signal_dbm,
                    suspicious_signal=sorted_nets[-1].signal_dbm,
                    reason=f"Same SSID with different security: "
                           f"{', '.join(securities)}",
                ))
                report.findings.append(
                    f"Possible evil twin: '{ssid}' has "
                    f"{len(nets)} BSSIDs with different security types")

    def _get_connected_network(self,
                                networks: list) -> Optional[WiFiNetwork]:
        # Check which network is currently connected
        connected_ssid = self._get_connected_ssid()
        if connected_ssid:
            for net in networks:
                if net.ssid == connected_ssid:
                    net.is_connected = True
                    return net
            # Not in scan (hidden?)
            return WiFiNetwork(ssid=connected_ssid, is_connected=True,
                               security=self._get_connected_security())
        return None

    def _get_connected_ssid(self) -> str:
        # Android / Linux
        for cmd in [
            "iw dev 2>/dev/null | grep ssid",
            "wpa_cli -i wlan0 status 2>/dev/null | grep ^ssid",
            "nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes'",
            "iwconfig wlan0 2>/dev/null | grep ESSID",
        ]:
            out = self._run(cmd)
            if out:
                m = re.search(r'[Ss][Ss][Ii][Dd][=:\s"]+([^\s"]+)', out)
                if m:
                    return m.group(1)
        # Windows
        if self._platform == "windows":
            out = self._run("netsh wlan show interfaces 2>NUL")
            m = re.search(r"SSID\s*:\s+(.+)", out)
            if m:
                return m.group(1).strip()
        return ""

    def _get_connected_security(self) -> str:
        for cmd in [
            "nmcli -t -f security con show --active 2>/dev/null | head -1",
        ]:
            out = self._run(cmd)
            if out:
                return self._clean_security(out.strip())
        return "UNKNOWN"

    def _assess_risk(self, report: WiFiSecurityReport):
        score = 0
        score += len(report.open_networks) * 30
        score += len(report.wep_networks)  * 25
        score += len(report.wps_networks)  * 15
        score += len(report.evil_twin_candidates) * 20

        # Connected network risk
        if report.connected_network:
            cn = report.connected_network
            if cn.security == "OPEN":
                score += 40
                report.findings.insert(0,
                    f"⚠ YOU ARE CONNECTED TO AN OPEN NETWORK: '{cn.ssid}'")
            elif cn.security == "WEP":
                score += 35
                report.findings.insert(0,
                    f"⚠ Connected to WEP network: '{cn.ssid}' — insecure!")
            elif cn.wps_enabled:
                report.findings.insert(0,
                    f"Connected network '{cn.ssid}' has WPS enabled")

        report.critical_count = (len(report.open_networks) +
                                  len(report.wep_networks))
        report.high_count     = (len(report.wps_networks) +
                                  len(report.evil_twin_candidates))

        if score >= 40:    report.risk_level = "CRITICAL"
        elif score >= 20:  report.risk_level = "HIGH"
        elif score >= 5:   report.risk_level = "MEDIUM"
        elif report.total_networks > 0: report.risk_level = "LOW"
        else:              report.risk_level = "UNKNOWN"

        # Recommendations
        if report.open_networks:
            report.recommendations.append(
                f"Avoid or use VPN on {len(report.open_networks)} open network(s) nearby")
        if report.wep_networks:
            report.recommendations.append(
                f"Upgrade {len(report.wep_networks)} WEP network(s) to WPA2/WPA3")
        if report.wps_networks:
            report.recommendations.append(
                "Disable WPS on your router — use strong WPA2/WPA3 password instead")
        if report.evil_twin_candidates:
            report.recommendations.append(
                "Possible evil twin detected — verify your network before connecting")
        if not report.findings:
            report.findings.append("No critical WiFi security issues found nearby")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _clean_security(self, raw: str) -> str:
        raw = raw.upper()
        if "OPEN" in raw or "NONE" in raw or not raw:
            return "OPEN"
        if "WPA3" in raw:
            return "WPA3"
        if "WPA2" in raw or "RSN" in raw:
            return "WPA2"
        if "WPA" in raw:
            return "WPA"
        if "WEP" in raw:
            return "WEP"
        return "UNKNOWN"

    def _flags_to_security(self, flags: str) -> str:
        if "[WPA2" in flags:    return "WPA2"
        if "[WPA3" in flags:    return "WPA3"
        if "[WPA" in flags:     return "WPA"
        if "[WEP" in flags:     return "WEP"
        if "[ESS]" == flags or not flags: return "OPEN"
        return "OPEN"

    def _get_wifi_interface_linux(self) -> str:
        try:
            out = subprocess.run(
                "iw dev 2>/dev/null | grep Interface",
                shell=True, capture_output=True, text=True, timeout=3
            ).stdout
            m = re.search(r"Interface\s+(\S+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        for iface in ["wlan0", "wlp2s0", "wifi0", "wlan1"]:
            if os.path.exists(f"/sys/class/net/{iface}"):
                return iface
        return ""

    @staticmethod
    def _detect_platform() -> str:
        if os.path.exists("/data/data/com.termux"):
            return "android"
        import platform
        return "windows" if "windows" in platform.system().lower() else "linux"

    @staticmethod
    def _run(cmd: str, timeout: int = 8) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    def _emit(self, pct: float, msg: str):
        if self._progress:
            try:
                self._progress(pct, msg)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# CLI runner
# ─────────────────────────────────────────────────────────────────────────────

def run_wifi_security_scan_cli() -> WiFiSecurityReport:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        console = Console()
    except ImportError:
        checker = WiFiSecurityChecker()
        r = checker.scan()
        for f in r.findings:
            print(f"  • {f}")
        return r

    console.print(Panel(
        "[bold cyan]WiFi Security Checker[/bold cyan]\n"
        "[dim]Scanning nearby networks for security vulnerabilities[/dim]",
        border_style="cyan",
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=35),
        console=console, transient=True,
    ) as prog:
        task = prog.add_task("Scanning...", total=100)
        def cb(pct, msg):
            prog.update(task, completed=pct, description=f"[dim]{msg}[/dim]")
        checker = WiFiSecurityChecker(progress_callback=cb)
        report = checker.scan()

    # Connected network
    if report.connected_network:
        cn = report.connected_network
        cn_color = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow",
                    "LOW":"cyan","SAFE":"green"}.get(cn.risk_level,"white")
        console.print(Panel(
            f"[bold]SSID    :[/bold] {cn.ssid}\n"
            f"[bold]Security:[/bold] [{cn_color}]{cn.security}[/{cn_color}]\n"
            f"[bold]Band    :[/bold] {cn.band}\n"
            f"[bold]WPS     :[/bold] {'[red]Enabled[/red]' if cn.wps_enabled else '[green]Disabled[/green]'}\n"
            f"[bold]Risk    :[/bold] [{cn_color}]{cn.risk_level}[/{cn_color}]",
            title="[bold]Connected Network[/bold]",
            border_style=cn_color,
        ))

    # All networks table
    if report.networks:
        t = Table(title=f"Nearby Networks [{report.total_networks}]",
                  show_lines=True)
        t.add_column("SSID",     style="cyan", no_wrap=True)
        t.add_column("Security", width=8)
        t.add_column("WPS",      width=5)
        t.add_column("Band",     width=6)
        t.add_column("Signal",   width=8)
        t.add_column("Risk",     width=10)
        t.add_column("Connected",width=3)

        for net in sorted(report.networks,
                          key=lambda n: (n.risk_level == "CRITICAL",
                                         n.risk_level == "HIGH"),
                          reverse=True):
            rc = net.risk_color
            sec_color = {"OPEN":"red","WEP":"red","WPA":"yellow",
                         "WPA2":"green","WPA3":"bold green"}.get(net.security,"")
            t.add_row(
                net.ssid[:28] or "[dim](hidden)[/dim]",
                f"[{sec_color}]{net.security}[/{sec_color}]",
                "[red]Yes[/red]" if net.wps_enabled else "[dim]No[/dim]",
                net.band,
                f"{net.signal_dbm} dBm" if net.signal_dbm else "?",
                f"[{rc}]{net.risk_level}[/{rc}]",
                "●" if net.is_connected else "",
            )
        console.print(t)

    # Summary
    rc = report.risk_color
    console.print(Panel(
        f"[bold]Total Networks:[/bold]  {report.total_networks}\n"
        f"[bold]Open Networks:[/bold]   [red]{len(report.open_networks)}[/red]\n"
        f"[bold]WEP Networks:[/bold]    [red]{len(report.wep_networks)}[/red]\n"
        f"[bold]WPS Enabled:[/bold]     [yellow]{len(report.wps_networks)}[/yellow]\n"
        f"[bold]Evil Twins:[/bold]      {'[red]' + str(len(report.evil_twin_candidates)) + '[/red]' if report.evil_twin_candidates else '[green]0[/green]'}\n"
        f"[bold]Risk Level:[/bold]      [{rc}]{report.risk_level}[/{rc}]",
        title="WiFi Security Summary",
        border_style=rc,
    ))

    if report.findings:
        console.print("\n[bold]Findings:[/bold]")
        for f in report.findings[:8]:
            prefix = "🔴" if "⚠" in f or "OPEN" in f or "WEP" in f else "⚠"
            console.print(f"  {prefix} {f}")

    if report.recommendations:
        console.print("\n[bold cyan]Recommendations:[/bold cyan]")
        for r in report.recommendations:
            console.print(f"  → {r}")

    return report