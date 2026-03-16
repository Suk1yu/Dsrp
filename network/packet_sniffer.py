"""
network/packet_sniffer.py
Captures and filters network packets using Scapy.
Requires root/elevated privileges in Termux.
"""

import asyncio
import threading
import queue
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text


PROTOCOL_FILTERS = {
    "ALL": None,
    "TCP": "tcp",
    "UDP": "udp",
    "DNS": "udp port 53",
    "HTTP": "tcp port 80",
    "HTTPS": "tcp port 443",
    "ICMP": "icmp",
}

SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 8888, 9999, 6667, 6666,
    12345, 54321, 7777, 2222, 5555,
}


@dataclass
class PacketRecord:
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    dns_query: str = ""
    flags: str = ""
    suspicious: bool = False
    raw_summary: str = ""

    def to_row(self):
        ts_short = self.timestamp.split("T")[1][:12] if "T" in self.timestamp else self.timestamp
        suspicious_mark = "⚠" if self.suspicious else ""
        return [
            ts_short,
            self.src_ip,
            self.dst_ip,
            str(self.dst_port),
            self.protocol,
            str(self.size),
            self.dns_query or self.flags,
            suspicious_mark,
        ]


class PacketSniffer:
    """
    Scapy-based packet capture with filtering and analysis.
    """

    def __init__(self,
                 interface: str = "wlan0",
                 protocol_filter: str = "ALL",
                 max_packets: int = 1000):
        self.interface = interface
        self.protocol_filter = protocol_filter
        self.max_packets = max_packets
        self._packets: list[PacketRecord] = []
        self._packet_queue: queue.Queue = queue.Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: list[Callable] = []
        self._stats = {
            "total": 0, "tcp": 0, "udp": 0, "dns": 0,
            "http": 0, "https": 0, "other": 0, "suspicious": 0
        }

    def add_callback(self, fn: Callable):
        """Register a callback invoked on each new packet."""
        self._callbacks.append(fn)

    def _parse_packet(self, pkt) -> Optional[PacketRecord]:
        try:
            if not pkt.haslayer(IP):
                return None

            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            size = len(pkt)
            ts = datetime.now().isoformat()
            dns_query = ""
            flags = ""
            src_port = 0
            dst_port = 0
            protocol = "OTHER"
            suspicious = False

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                flags = str(tcp.flags)
                if dst_port == 80 or src_port == 80:
                    protocol = "HTTP"
                    self._stats["http"] += 1
                elif dst_port == 443 or src_port == 443:
                    protocol = "HTTPS"
                    self._stats["https"] += 1
                else:
                    protocol = "TCP"
                    self._stats["tcp"] += 1
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                if dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                    self._stats["dns"] += 1
                    if pkt.haslayer(DNSQR):
                        dns_query = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                else:
                    protocol = "UDP"
                    self._stats["udp"] += 1
            else:
                self._stats["other"] += 1

            # Suspicious check
            if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
                suspicious = True
                self._stats["suspicious"] += 1

            self._stats["total"] += 1

            record = PacketRecord(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=size,
                dns_query=dns_query,
                flags=flags,
                suspicious=suspicious,
                raw_summary=pkt.summary(),
            )
            return record
        except Exception:
            return None

    def _scapy_callback(self, pkt):
        record = self._parse_packet(pkt)
        if record:
            self._packet_queue.put(record)
            for cb in self._callbacks:
                try:
                    cb(record)
                except Exception:
                    pass

    def start(self, count: int = 0):
        """Start sniffing in background thread."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available. Install: pip install scapy")

        self._running = True
        bpf = PROTOCOL_FILTERS.get(self.protocol_filter.upper(), None)

        def _sniff():
            sniff(
                iface=self.interface,
                prn=self._scapy_callback,
                filter=bpf,
                store=False,
                stop_filter=lambda _: not self._running,
                count=count if count > 0 else 0,
            )

        self._thread = threading.Thread(target=_sniff, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def get_packets(self, limit: int = 100) -> list[PacketRecord]:
        """Drain queue and return recent packets."""
        while not self._packet_queue.empty():
            try:
                pkt = self._packet_queue.get_nowait()
                self._packets.append(pkt)
            except queue.Empty:
                break
        # Keep only last max_packets
        if len(self._packets) > self.max_packets:
            self._packets = self._packets[-self.max_packets:]
        return self._packets[-limit:]

    def get_stats(self) -> dict:
        return dict(self._stats)

    def run_cli(self, count: int = 200):
        """Interactive CLI packet viewer."""
        if not SCAPY_AVAILABLE:
            print("Error: scapy not installed. Run: pip install scapy")
            return

        console = Console()
        console.print(f"\n[bold cyan]DSRP Packet Sniffer[/bold cyan]")
        console.print(f"Interface: [yellow]{self.interface}[/yellow] | "
                      f"Filter: [yellow]{self.protocol_filter}[/yellow]\n")
        console.print("[dim]Starting capture... Press Ctrl+C to stop[/dim]\n")

        packets_shown = []

        def on_packet(record: PacketRecord):
            packets_shown.append(record)

        self.add_callback(on_packet)
        self.start()

        try:
            with Live(refresh_per_second=2) as live:
                while True:
                    table = Table(title=f"Packets [{self._stats['total']}]",
                                  show_lines=False, expand=True)
                    table.add_column("Time", width=13)
                    table.add_column("Src IP", width=16)
                    table.add_column("Dst IP", width=16)
                    table.add_column("Port", width=6)
                    table.add_column("Proto", width=6)
                    table.add_column("Bytes", width=7)
                    table.add_column("Info", no_wrap=False)
                    table.add_column("⚠", width=2)

                    for pkt in packets_shown[-30:]:
                        row = pkt.to_row()
                        style = "red" if pkt.suspicious else ""
                        table.add_row(*row, style=style)

                    live.update(table)
                    time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()
            console.print("\n[yellow]Capture stopped.[/yellow]")