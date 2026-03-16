"""
network/vpn_leak_detector.py

VPN Leak Detector — checks if traffic/DNS leaks outside the VPN tunnel.

Tests performed:
  1. VPN Detection     — is a VPN/tunnel interface active?
  2. Public IP Check   — current external IP vs expected
  3. DNS Leak Test     — DNS queries going through VPN or bypassing it?
  4. Routing Table     — are there routes that bypass the VPN?
  5. Interface Audit   — list all active network interfaces + their routes

Cross-platform: Android (Termux), Linux, Windows.
No root required for most tests.
"""

import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
import ssl
from dataclasses import dataclass, field
from typing import Optional


# ── DNS servers used for leak test ────────────────────────────────────────────
# These are servers associated with VPN providers — if your DNS resolves
# through these, you're not leaking. If it goes to your ISP's DNS, you are.
LEAK_TEST_DOMAINS = [
    "whoami.akamai.net",     # returns resolver IP in TXT
    "o-o.myaddr.l.google.com",  # Google's DNS leak test domain
    "myip.opendns.com",      # OpenDNS leak test
]

# Public IP check services
IP_CHECK_URLS = [
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://icanhazip.com",
    "https://ip4.seeip.org",
]

# Known VPN/proxy IP ranges (very partial — for heuristic detection only)
VPN_INTERFACE_PREFIXES = {
    "tun":    "OpenVPN / WireGuard tunnel",
    "wg":     "WireGuard",
    "ppp":    "PPP VPN",
    "vpn":    "Generic VPN",
    "ipsec":  "IPsec VPN",
    "tap":    "TAP VPN",
    "nordlynx": "NordVPN WireGuard",
    "proton": "ProtonVPN",
}

# ─────────────────────────────────────────────────────────────────────────────
# Result dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VPNInterface:
    name: str
    vpn_type: str
    ip_address: str = ""
    is_active: bool = True


@dataclass
class DNSLeakResult:
    domain: str
    resolved_ips: list = field(default_factory=list)
    resolver_ip: str = ""
    latency_ms: float = 0.0
    looks_like_vpn: bool = False
    looks_like_isp: bool = False


@dataclass
class RouteEntry:
    destination: str
    gateway: str
    interface: str
    metric: int = 0
    is_default: bool = False
    bypasses_vpn: bool = False


@dataclass
class VPNLeakReport:
    timestamp: float = field(default_factory=time.time)
    platform: str = ""

    # VPN detection
    vpn_detected: bool = False
    vpn_interfaces: list = field(default_factory=list)

    # IP results
    public_ip_before: str = ""   # without VPN context
    public_ip_current: str = ""
    ip_looks_like_vpn: bool = False

    # DNS leak
    dns_leak_detected: bool = False
    dns_results: list = field(default_factory=list)
    dns_servers_used: list = field(default_factory=list)
    leaked_to_isp: bool = False

    # Routing
    route_entries: list = field(default_factory=list)
    suspicious_routes: list = field(default_factory=list)
    split_tunnel_detected: bool = False

    # Overall
    leak_detected: bool = False
    risk_level: str = "UNKNOWN"   # SAFE / LOW / MEDIUM / HIGH / CRITICAL
    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    scan_duration_secs: float = 0.0
    error: str = ""

    @property
    def risk_color(self) -> str:
        return {
            "SAFE":     "#3FB950",
            "LOW":      "#58A6FF",
            "MEDIUM":   "#F0B429",
            "HIGH":     "#FF7B72",
            "CRITICAL": "bold #FF7B72",
            "UNKNOWN":  "#6E7681",
        }.get(self.risk_level, "#C9D1D9")

    def summary(self) -> str:
        lines = [
            f"VPN Detected   : {'Yes' if self.vpn_detected else 'No'}",
            f"Current IP     : {self.public_ip_current}",
            f"DNS Leak       : {'⚠ YES' if self.dns_leak_detected else '✓ No'}",
            f"Split Tunnel   : {'⚠ YES' if self.split_tunnel_detected else '✓ No'}",
            f"Risk Level     : {self.risk_level}",
        ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────────────────

class VPNLeakDetector:
    """
    Multi-test VPN leak detector.
    Works on Android (Termux), Linux, and Windows.
    No root required.
    """

    TIMEOUT = 5   # seconds per network call

    def __init__(self, progress_callback=None):
        self._progress = progress_callback
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._platform = self._detect_platform()

    def run(self) -> VPNLeakReport:
        """Run all leak tests. Returns VPNLeakReport."""
        report = VPNLeakReport(platform=self._platform)
        t0 = time.time()

        self._emit(5, "Detecting VPN interfaces...")
        self._check_vpn_interfaces(report)

        self._emit(25, "Checking public IP...")
        self._check_public_ip(report)

        self._emit(45, "Running DNS leak test...")
        self._check_dns_leak(report)

        self._emit(70, "Analysing routing table...")
        self._check_routing(report)

        self._emit(90, "Calculating risk level...")
        self._assess_risk(report)

        report.scan_duration_secs = round(time.time() - t0, 1)
        self._emit(100, f"Done in {report.scan_duration_secs}s")
        return report

    # ── 1. VPN interface detection ────────────────────────────────────────────

    def _check_vpn_interfaces(self, report: VPNLeakReport):
        interfaces = self._get_interfaces()
        vpn_ifaces = []

        for name, ip in interfaces.items():
            name_lower = name.lower()
            for prefix, vpn_type in VPN_INTERFACE_PREFIXES.items():
                if name_lower.startswith(prefix):
                    vpn_ifaces.append(VPNInterface(
                        name=name, vpn_type=vpn_type,
                        ip_address=ip, is_active=True,
                    ))
                    break

        # Also check /proc/net/dev on Linux/Android for tun interfaces
        try:
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    iface = line.split(":")[0].strip()
                    if any(iface.startswith(p)
                           for p in VPN_INTERFACE_PREFIXES):
                        if not any(v.name == iface for v in vpn_ifaces):
                            vpn_type = next(
                                (t for p, t in VPN_INTERFACE_PREFIXES.items()
                                 if iface.startswith(p)), "VPN")
                            vpn_ifaces.append(VPNInterface(
                                name=iface, vpn_type=vpn_type))
        except Exception:
            pass

        report.vpn_interfaces  = vpn_ifaces
        report.vpn_detected    = len(vpn_ifaces) > 0

        if vpn_ifaces:
            report.findings.append(
                f"VPN interface detected: "
                f"{', '.join(v.name for v in vpn_ifaces)}")

    def _get_interfaces(self) -> dict:
        """Return {interface_name: ip_address}."""
        interfaces = {}

        # Try psutil first
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for name, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        interfaces[name] = addr.address
            return interfaces
        except ImportError:
            pass

        # Fallback: /proc/net/if_inet6 + ip addr
        try:
            out = subprocess.run(
                "ip addr show 2>/dev/null || ifconfig 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            ).stdout
            current = None
            for line in out.splitlines():
                m = re.match(r"^\d+:\s+(\S+):", line)
                if m:
                    current = m.group(1).rstrip(":")
                inet = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
                if inet and current:
                    interfaces[current] = inet.group(1)
        except Exception:
            pass

        # Windows
        if self._platform == "windows":
            try:
                out = subprocess.run(
                    "ipconfig", shell=True,
                    capture_output=True, text=True, timeout=5
                ).stdout
                current = "unknown"
                for line in out.splitlines():
                    adapter = re.match(r"^(\w[^:]+):", line)
                    if adapter:
                        current = adapter.group(1).strip()
                    ip = re.search(r"IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)", line)
                    if ip:
                        interfaces[current] = ip.group(1)
            except Exception:
                pass

        return interfaces

    # ── 2. Public IP check ────────────────────────────────────────────────────

    def _check_public_ip(self, report: VPNLeakReport):
        for url in IP_CHECK_URLS:
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "VPNLeakTest/1.0"})
                with urllib.request.urlopen(
                        req, timeout=self.TIMEOUT,
                        context=self._ctx) as r:
                    ip = r.read().decode().strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                        report.public_ip_current = ip
                        break
            except Exception:
                continue

        # Heuristic: Datacenter IPs are often VPN exit nodes
        # (simple check — real geo-IP lookup would need API)
        if report.public_ip_current:
            report.ip_looks_like_vpn = report.vpn_detected

    # ── 3. DNS leak test ──────────────────────────────────────────────────────

    def _check_dns_leak(self, report: VPNLeakReport):
        # Method 1: Resolve test domains and check resolver
        dns_results = []
        resolver_ips = set()

        for domain in LEAK_TEST_DOMAINS:
            result = self._dns_query(domain)
            dns_results.append(result)
            if result.resolver_ip:
                resolver_ips.add(result.resolver_ip)

        report.dns_results    = dns_results
        report.dns_servers_used = list(resolver_ips)

        # Method 2: Check /etc/resolv.conf (Linux/Android)
        configured_dns = self._read_resolv_conf()
        if configured_dns:
            report.dns_servers_used = list(
                set(report.dns_servers_used + configured_dns))

        # Method 3: Check if DNS is going through VPN
        # If VPN is detected but DNS servers are ISP ranges → leak
        if report.vpn_detected and report.dns_servers_used:
            for dns_ip in report.dns_servers_used:
                # Private IP ranges used as DNS = likely VPN's own DNS
                if self._is_private_ip(dns_ip) or \
                   self._is_vpn_ip(dns_ip, report):
                    continue
                else:
                    # Public DNS that isn't through VPN = potential leak
                    report.leaked_to_isp    = True
                    report.dns_leak_detected = True
                    report.findings.append(
                        f"DNS server {dns_ip} may be outside VPN tunnel")

        # Check for split DNS (some queries bypass VPN)
        if not report.vpn_detected:
            report.dns_leak_detected = False  # No VPN = no leak by definition

    def _dns_query(self, domain: str) -> DNSLeakResult:
        result = DNSLeakResult(domain=domain)
        try:
            t0 = time.perf_counter()
            infos = socket.getaddrinfo(domain, None)
            result.latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            result.resolved_ips = list({i[4][0] for i in infos})
            # If myip domain, the IP is the resolver
            if "myip" in domain or "myaddr" in domain or "opendns" in domain:
                result.resolver_ip = result.resolved_ips[0] \
                    if result.resolved_ips else ""
        except Exception as e:
            result.resolved_ips = []
        return result

    def _read_resolv_conf(self) -> list:
        """Read configured DNS servers."""
        dns_servers = []
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    m = re.match(r"^nameserver\s+(\S+)", line.strip())
                    if m:
                        dns_servers.append(m.group(1))
        except Exception:
            pass

        # Android: also check /data/misc/dns
        for path in ["/data/misc/dhcp/dhcpcd-*.conf",
                     "/data/misc/net/resolv.conf"]:
            try:
                import glob
                for f in glob.glob(path):
                    with open(f) as fp:
                        for line in fp:
                            m = re.search(r"domain_name_servers=(.+)", line)
                            if m:
                                dns_servers.extend(
                                    m.group(1).strip().split())
            except Exception:
                pass

        # Windows: use ipconfig /all
        if self._platform == "windows":
            try:
                out = subprocess.run(
                    "ipconfig /all", shell=True,
                    capture_output=True, text=True, timeout=5
                ).stdout
                for m in re.finditer(r"DNS Servers.*?:\s+(\S+)", out):
                    dns_servers.append(m.group(1))
            except Exception:
                pass

        return list(set(dns_servers))

    # ── 4. Routing table ──────────────────────────────────────────────────────

    def _check_routing(self, report: VPNLeakReport):
        routes = []

        if self._platform in ("linux", "android"):
            routes = self._read_routes_linux()
        elif self._platform == "windows":
            routes = self._read_routes_windows()

        report.route_entries = routes

        # Detect suspicious routes: default route NOT through VPN
        vpn_iface_names = {v.name for v in report.vpn_interfaces}
        default_routes  = [r for r in routes if r.is_default]

        for route in default_routes:
            if route.interface and vpn_iface_names and \
               route.interface not in vpn_iface_names:
                route.bypasses_vpn = True
                report.suspicious_routes.append(route)
                report.split_tunnel_detected = True
                report.findings.append(
                    f"Default route via {route.interface} "
                    f"(not VPN) — possible split tunnel")

    def _read_routes_linux(self) -> list:
        routes = []
        try:
            # /proc/net/route — hex format
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 8:
                        continue
                    iface = parts[0]
                    dest  = self._hex_to_ip(parts[1])
                    gw    = self._hex_to_ip(parts[2])
                    try:
                        metric = int(parts[6], 16)
                    except Exception:
                        metric = 0
                    is_default = (dest == "0.0.0.0")
                    routes.append(RouteEntry(
                        destination=dest, gateway=gw,
                        interface=iface, metric=metric,
                        is_default=is_default,
                    ))
        except Exception:
            pass
        return routes

    def _read_routes_windows(self) -> list:
        routes = []
        try:
            out = subprocess.run(
                "route print -4", shell=True,
                capture_output=True, text=True, timeout=5
            ).stdout
            for line in out.splitlines():
                m = re.match(
                    r"\s*(\d+\.\d+\.\d+\.\d+)\s+"
                    r"(\d+\.\d+\.\d+\.\d+)\s+"
                    r"(\d+\.\d+\.\d+\.\d+)\s+"
                    r"(\d+\.\d+\.\d+\.\d+)\s+(\d+)", line)
                if m:
                    dest = m.group(1)
                    routes.append(RouteEntry(
                        destination=dest,
                        gateway=m.group(3),
                        interface=m.group(4),
                        metric=int(m.group(5)),
                        is_default=(dest == "0.0.0.0"),
                    ))
        except Exception:
            pass
        return routes

    # ── 5. Risk assessment ────────────────────────────────────────────────────

    def _assess_risk(self, report: VPNLeakReport):
        score = 0

        if not report.vpn_detected:
            report.risk_level = "SAFE"
            report.findings.insert(0, "No VPN detected — nothing to leak")
            report.recommendations.append(
                "Consider using a VPN for privacy on public networks")
            return

        # VPN is active — check for leaks
        if report.dns_leak_detected:
            score += 40
        if report.split_tunnel_detected:
            score += 30
        if report.leaked_to_isp:
            score += 30
        if report.suspicious_routes:
            score += 20

        if score == 0:
            report.risk_level = "SAFE"
            report.findings.append(
                "VPN active — no leaks detected")
            report.recommendations.append(
                "Continue monitoring. Run test on different networks.")
        elif score < 30:
            report.risk_level = "LOW"
            report.recommendations.append(
                "Minor leak indicators. Consider enabling VPN kill switch.")
        elif score < 60:
            report.risk_level = "MEDIUM"
            report.leak_detected = True
            report.recommendations.append(
                "DNS leak likely. Enable DNS-over-VPN in your VPN app.")
            report.recommendations.append(
                "Set DNS servers to VPN provider's DNS manually.")
        else:
            report.risk_level = "HIGH"
            report.leak_detected = True
            report.recommendations.append(
                "Significant VPN leak detected. Your ISP can see your DNS queries.")
            report.recommendations.append(
                "Enable kill switch in VPN app. Disable split tunneling.")
            report.recommendations.append(
                "Consider switching to a VPN app with leak protection.")

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _detect_platform() -> str:
        if os.path.exists("/data/data/com.termux"):
            return "android"
        import platform
        s = platform.system().lower()
        return "windows" if "windows" in s else "linux"

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            parts = [int(x) for x in ip.split(".")]
            return (parts[0] == 10 or
                    (parts[0] == 172 and 16 <= parts[1] <= 31) or
                    (parts[0] == 192 and parts[1] == 168))
        except Exception:
            return False

    @staticmethod
    def _is_vpn_ip(ip: str, report: VPNLeakReport) -> bool:
        """Heuristic: is this IP part of VPN's infrastructure?"""
        for iface in report.vpn_interfaces:
            if iface.ip_address and iface.ip_address.startswith(
                    ".".join(ip.split(".")[:2])):
                return True
        return False

    @staticmethod
    def _hex_to_ip(hex_str: str) -> str:
        try:
            n = int(hex_str, 16)
            return f"{n&0xff}.{(n>>8)&0xff}.{(n>>16)&0xff}.{(n>>24)&0xff}"
        except Exception:
            return hex_str

    def _emit(self, pct: float, msg: str):
        if self._progress:
            try:
                self._progress(pct, msg)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# CLI runner
# ─────────────────────────────────────────────────────────────────────────────

def run_vpn_leak_test_cli() -> VPNLeakReport:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        console = Console()
    except ImportError:
        d = VPNLeakDetector()
        r = d.run()
        print(r.summary())
        return r

    console.print(Panel(
        "[bold cyan]VPN Leak Detector[/bold cyan]\n"
        "[dim]Tests: VPN detection · DNS leak · IP leak · Routing analysis[/dim]",
        border_style="cyan",
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[cyan]{task.percentage:>3.0f}%[/cyan]"),
        console=console, transient=True,
    ) as prog:
        task = prog.add_task("Running...", total=100)
        def cb(pct, msg):
            prog.update(task, completed=pct, description=f"[dim]{msg}[/dim]")
        detector = VPNLeakDetector(progress_callback=cb)
        report = detector.run()

    # Result panel
    rc = report.risk_color
    console.print(Panel(
        f"[bold]VPN Detected  :[/bold] {'[green]Yes[/green]' if report.vpn_detected else '[dim]No[/dim]'}\n"
        f"[bold]VPN Interfaces:[/bold] {', '.join(v.name+' ('+v.vpn_type+')' for v in report.vpn_interfaces) or 'none'}\n"
        f"[bold]Public IP     :[/bold] {report.public_ip_current or 'unknown'}\n"
        f"[bold]DNS Leak      :[/bold] {'[red]⚠ DETECTED[/red]' if report.dns_leak_detected else '[green]✓ Clean[/green]'}\n"
        f"[bold]Split Tunnel  :[/bold] {'[yellow]⚠ Detected[/yellow]' if report.split_tunnel_detected else '[green]✓ None[/green]'}\n"
        f"[bold]Risk Level    :[/bold] [{rc}]{report.risk_level}[/{rc}]\n"
        f"[bold]Scan Duration :[/bold] {report.scan_duration_secs}s",
        title="VPN Leak Test Results",
        border_style=rc,
    ))

    if report.dns_servers_used:
        console.print(f"\n[bold]DNS Servers in use:[/bold]")
        for dns in report.dns_servers_used:
            is_private = VPNLeakDetector._is_private_ip(dns)
            flag = "[green](private/VPN)[/green]" if is_private else "[yellow](public)[/yellow]"
            console.print(f"  • {dns}  {flag}")

    if report.findings:
        console.print(f"\n[bold]Findings:[/bold]")
        for f in report.findings:
            console.print(f"  • {f}")

    if report.recommendations:
        console.print(f"\n[bold cyan]Recommendations:[/bold cyan]")
        for r in report.recommendations:
            console.print(f"  → {r}")

    return report