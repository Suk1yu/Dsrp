"""
network/network_mapper.py  (Stage 2 lightweight rewrite)

Periodic WiFi device discovery — scan every 120s, idle otherwise.
Methods: ARP cache > arp-scan > nmap -sn > ping sweep
CPU cost: Near-zero between scans, ~5% during 5-10s scan window.
"""

import re
import subprocess
import ipaddress
import socket
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import nmap
    NMAP_OK = True
except ImportError:
    NMAP_OK = False

MAC_VENDORS: dict = {
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "00:50:56": "VMware",       "00:0C:29": "VMware",
    "3C:07:54": "Apple",        "F0:DB:F8": "Apple",
    "54:60:09": "Samsung",      "8C:77:12": "Samsung",
    "18:C0:4D": "Huawei",       "58:A0:23": "Xiaomi",
    "00:1A:11": "Google",       "00:26:B9": "Dell",
    "74:23:44": "Amazon",
}


@dataclass
class WiFiDevice:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    open_ports: list = field(default_factory=list)
    state: str = "up"
    source: str = "arp"
    last_seen: float = field(default_factory=time.time)

    @property
    def display_name(self) -> str:
        return self.hostname or (f"{self.vendor} device" if self.vendor else self.ip)

    def to_row(self) -> list:
        ports = ", ".join(str(p) for p in self.open_ports[:5]) or "—"
        ts = time.strftime("%H:%M:%S", time.localtime(self.last_seen))
        return [self.ip, self.mac or "—", self.display_name[:25],
                self.vendor[:20] or "—", ports, ts]

    def ascii_line(self) -> str:
        return f"{self.ip:<16} {self.display_name:<25}  {self.mac}"


@dataclass
class NetworkScanResult:
    timestamp: float
    network: str
    devices: list = field(default_factory=list)
    scan_method: str = ""
    duration_secs: float = 0.0


class NetworkMapper:
    """Periodic WiFi device scanner. Idle between scans."""

    def __init__(self, scan_interval: float = 120.0):
        self.scan_interval = scan_interval
        self._devices: dict = {}
        self._last_scan: Optional[NetworkScanResult] = None
        self._scan_callbacks: list[Callable] = []
        self._running = False
        self._scanning = False
        self._thread: Optional[threading.Thread] = None

    def add_scan_callback(self, fn: Callable):
        self._scan_callbacks.append(fn)

    def start_periodic(self):
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name="net-mapper")
        self._thread.start()

    def stop(self):
        self._running = False

    def scan_now(self, target: str = None) -> NetworkScanResult:
        network = target or self._detect_local_network()
        return self._do_scan(network)

    def get_devices(self) -> list:
        return sorted(self._devices.values(), key=lambda d: self._ip_key(d.ip))

    def get_last_scan(self) -> Optional[NetworkScanResult]:
        return self._last_scan

    def is_scanning(self) -> bool:
        return self._scanning

    def get_device_count(self) -> int:
        return len(self._devices)

    def get_ascii_list(self) -> str:
        devs = self.get_devices()
        if not devs:
            return "(no devices — run a scan)"
        lines = [f"WiFi Devices [{len(devs)}]:"]
        for d in devs:
            lines.append("  " + d.ascii_line())
        return "\n".join(lines)

    def _scan_loop(self):
        while self._running:
            try:
                network = self._detect_local_network()
                self._do_scan(network)
            except Exception:
                pass
            for _ in range(int(self.scan_interval / 2)):
                if not self._running:
                    break
                time.sleep(2)

    def _do_scan(self, network: str) -> NetworkScanResult:
        self._scanning = True
        t0 = time.time()
        devices = []
        method = "arp-cache"

        try:
            # 1. ARP cache — instant, zero overhead
            devices = self._read_arp_cache()

            # 2. arp-scan if sparse
            if len(devices) < 2:
                devices += self._arping_scan(network)
                method = "arp-scan"

            # 3. nmap -sn
            if NMAP_OK and len(devices) < 2:
                devices += self._nmap_scan(network)
                method = "nmap"

            # 4. ping sweep last resort
            if len(devices) == 0:
                devices = self._ping_sweep(network)
                method = "ping"

        except Exception:
            pass

        now = time.time()
        for dev in devices:
            dev.last_seen = now
            if not dev.hostname:
                dev.hostname = self._resolve(dev.ip)
            if not dev.vendor and dev.mac:
                dev.vendor = self._vendor(dev.mac)
            self._devices[dev.ip] = dev

        result = NetworkScanResult(
            timestamp=now,
            network=network,
            devices=list(self._devices.values()),
            scan_method=method,
            duration_secs=round(time.time() - t0, 2),
        )
        self._last_scan = result
        self._scanning = False
        for cb in self._scan_callbacks:
            try: cb(result)
            except Exception: pass
        return result

    def _read_arp_cache(self) -> list:
        devices = []
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                        devices.append(WiFiDevice(ip=p[0], mac=p[3], source="arp"))
        except Exception:
            pass
        return devices

    def _arping_scan(self, network: str) -> list:
        devices = []
        try:
            out = subprocess.run(
                f"arp-scan --localnet 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=15).stdout
            for line in out.splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)", line.lower())
                if m:
                    devices.append(WiFiDevice(ip=m.group(1), mac=m.group(2), source="arp-scan"))
        except Exception:
            pass
        return devices

    def _nmap_scan(self, network: str) -> list:
        devices = []
        try:
            s = nmap.PortScanner()
            s.scan(hosts=network, arguments="-sn -T4")
            for host in s.all_hosts():
                d = WiFiDevice(ip=host, source="nmap")
                addrs = s[host].get("addresses", {})
                d.mac = addrs.get("mac", "")
                vendor = s[host].get("vendor", {})
                if vendor and d.mac:
                    d.vendor = list(vendor.values())[0]
                hn = s[host].hostnames()
                if hn:
                    d.hostname = hn[0].get("name", "")
                devices.append(d)
        except Exception:
            pass
        return devices

    def _ping_sweep(self, network: str) -> list:
        devices = []
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = list(net.hosts())[:64]
            results = {}
            lock = threading.Lock()

            def ping(ip_obj):
                ip = str(ip_obj)
                try:
                    r = subprocess.run(f"ping -c 1 -W 1 {ip}",
                                       shell=True, capture_output=True, timeout=2)
                    if r.returncode == 0:
                        with lock: results[ip] = True
                except Exception: pass

            threads = [threading.Thread(target=ping, args=(h,)) for h in hosts]
            for t in threads: t.start()
            for t in threads: t.join(timeout=3)
            for ip in results:
                devices.append(WiFiDevice(ip=ip, source="ping"))
        except Exception:
            pass
        return devices

    def _detect_local_network(self) -> str:
        try:
            out = subprocess.run("ip route show", shell=True,
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                if "/" in line and "src" in line and "default" not in line:
                    p = line.split()
                    if "/" in p[0]:
                        return p[0]
        except Exception:
            pass
        if PSUTIL_OK:
            try:
                for iface, addr_list in psutil.net_if_addrs().items():
                    if "lo" in iface:
                        continue
                    for addr in addr_list:
                        if addr.family == socket.AF_INET and addr.address:
                            net = ipaddress.IPv4Network(
                                f"{addr.address}/{addr.netmask or '255.255.255.0'}", strict=False)
                            return str(net)
            except Exception:
                pass
        return "192.168.1.0/24"

    def _resolve(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _vendor(self, mac: str) -> str:
        if len(mac) >= 8:
            return MAC_VENDORS.get(mac[:8].upper(), "")
        return ""

    @staticmethod
    def _ip_key(ip: str):
        try: return tuple(int(x) for x in ip.split("."))
        except Exception: return (0,0,0,0)

    def run_cli(self, target: str = None):
        from rich.console import Console
        from rich.table import Table
        console = Console()
        console.print("\n[bold cyan]DSRP Network Mapper (Stage 2)[/bold cyan]")
        net = target or self._detect_local_network()
        console.print(f"Scanning [yellow]{net}[/yellow]…\n")
        result = self.scan_now(net)
        table = Table(title=f"Devices [{len(result.devices)}] via {result.scan_method} ({result.duration_secs}s)", show_lines=True)
        table.add_column("IP", style="cyan"); table.add_column("MAC", style="dim")
        table.add_column("Name"); table.add_column("Vendor", style="yellow")
        table.add_column("Ports"); table.add_column("Seen")
        for dev in result.devices:
            table.add_row(*dev.to_row())
        console.print(table)