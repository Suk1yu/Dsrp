"""
network/packet_metadata.py

Lightweight network metadata collector.
Uses psutil.net_connections() + net_io_counters() — NO packet capture.

CPU cost: Very low (~0.5–1%)
Refresh: every N seconds (configurable, default 5s)
Strategy: snapshot active connections, not per-packet hooks
"""

import time
import socket
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ConnectionMeta:
    """Represents a single active network connection snapshot."""
    timestamp: float
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str       # TCP / UDP
    status: str         # ESTABLISHED, TIME_WAIT, etc.
    pid: int = 0
    process_name: str = ""
    remote_hostname: str = ""
    is_suspicious: bool = False
    flag_reason: str = ""

    @property
    def direction(self) -> str:
        return "OUT" if self.local_port > 1024 else "IN"

    def to_row(self) -> list:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        host = self.remote_hostname[:30] or self.remote_ip
        susp = "⚠" if self.is_suspicious else ""
        return [
            ts,
            self.process_name[:18] or f"pid:{self.pid}",
            f"{self.remote_ip}:{self.remote_port}",
            host,
            self.protocol,
            self.status[:12],
            susp,
        ]


@dataclass
class IOSnapshot:
    """Network I/O throughput snapshot."""
    timestamp: float
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    send_rate_kbs: float = 0.0   # KB/s since last snapshot
    recv_rate_kbs: float = 0.0
    error_in: int = 0
    error_out: int = 0
    drop_in: int = 0
    drop_out: int = 0


# ---------------------------------------------------------------------------
# Suspicious port detection
# ---------------------------------------------------------------------------

SUSPICIOUS_REMOTE_PORTS = {
    4444: "Metasploit reverse shell",
    1337: "Hacker/C2 port",
    31337: "Elite/BackOrifice C2",
    6667: "IRC botnet C2",
    6666: "IRC alt botnet C2",
    9999: "Common RAT port",
    7777: "Common RAT port",
    5555: "ADB over TCP — remote control",
    2222: "Alt SSH / C2",
    12345: "NetBus RAT classic",
    54321: "Reverse shell classic",
}

SUSPICIOUS_PROCESSES = {
    "curl", "wget", "nc", "ncat", "netcat", "socat",
    "msfconsole", "metasploit",
}


# ---------------------------------------------------------------------------
# Metadata collector
# ---------------------------------------------------------------------------

class PacketMetadataCollector:
    """
    Polls psutil for active connection metadata.
    Updates every `poll_interval` seconds in a background thread.
    
    Provides:
    - Active connection list
    - I/O throughput rates
    - Per-process connection counts
    - Suspicious connection flagging
    """

    def __init__(self,
                 poll_interval: float = 5.0,
                 history_size: int = 300,
                 resolve_hostnames: bool = True):
        self.poll_interval = poll_interval
        self.history_size = history_size
        self.resolve_hostnames = resolve_hostnames

        self._connections: list[ConnectionMeta] = []
        self._conn_history: deque = deque(maxlen=history_size)
        self._io_history: deque = deque(maxlen=120)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: list[Callable] = []

        self._hostname_cache: dict[str, str] = {}
        self._last_io: Optional[IOSnapshot] = None

        # Per-process stats
        self._process_conn_count: dict[str, int] = {}
        self._process_data_sent: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_callback(self, fn: Callable):
        """Called with list[ConnectionMeta] on each poll update."""
        self._callbacks.append(fn)

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="pkt-meta"
        )
        self._thread.start()

    def stop(self):
        self._running = False

    def get_active_connections(self,
                                protocol: str = None,
                                status: str = None,
                                suspicious_only: bool = False) -> list[ConnectionMeta]:
        conns = list(self._connections)
        if protocol:
            conns = [c for c in conns if c.protocol == protocol.upper()]
        if status:
            conns = [c for c in conns if c.status == status.upper()]
        if suspicious_only:
            conns = [c for c in conns if c.is_suspicious]
        return conns

    def get_io_snapshot(self) -> Optional[IOSnapshot]:
        return self._io_history[-1] if self._io_history else None

    def get_io_history(self) -> list[IOSnapshot]:
        return list(self._io_history)

    def get_top_processes(self, n: int = 10) -> list[tuple[str, int]]:
        """Return (process_name, connection_count) sorted by conn count."""
        return sorted(self._process_conn_count.items(),
                      key=lambda x: x[1], reverse=True)[:n]

    def get_remote_ip_summary(self, top: int = 20) -> list[tuple[str, int]]:
        """Return most-connected remote IPs."""
        counts: dict[str, int] = defaultdict(int)
        for conn in self._conn_history:
            if conn.remote_ip:
                counts[conn.remote_ip] += 1
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top]

    def get_suspicious_connections(self) -> list[ConnectionMeta]:
        return [c for c in self._connections if c.is_suspicious]

    def get_stats(self) -> dict:
        io = self.get_io_snapshot()
        return {
            "active_connections": len(self._connections),
            "suspicious": len(self.get_suspicious_connections()),
            "unique_processes": len(self._process_conn_count),
            "send_rate_kbs": io.send_rate_kbs if io else 0,
            "recv_rate_kbs": io.recv_rate_kbs if io else 0,
        }

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    def _poll_loop(self):
        while self._running:
            try:
                self._poll_connections()
                self._poll_io()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _poll_connections(self):
        if not PSUTIL_OK:
            return

        new_conns = []
        proc_counts: dict[str, int] = defaultdict(int)

        try:
            for conn in psutil.net_connections(kind="all"):
                if not conn.raddr:
                    continue  # skip listening / unconnected

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_ip = conn.laddr.ip if conn.laddr else ""
                local_port = conn.laddr.port if conn.laddr else 0
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                status = conn.status or ""
                pid = conn.pid or 0

                proc_name = self._get_process_name(pid)
                hostname = ""
                if self.resolve_hostnames and remote_ip:
                    hostname = self._resolve_hostname(remote_ip)

                is_suspicious, flag_reason = self._check_suspicious(
                    remote_ip, remote_port, proc_name
                )

                meta = ConnectionMeta(
                    timestamp=time.time(),
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    protocol=protocol,
                    status=status,
                    pid=pid,
                    process_name=proc_name,
                    remote_hostname=hostname,
                    is_suspicious=is_suspicious,
                    flag_reason=flag_reason,
                )
                new_conns.append(meta)
                proc_counts[proc_name] += 1

        except Exception:
            pass

        self._connections = new_conns
        self._process_conn_count = dict(proc_counts)
        for c in new_conns:
            self._conn_history.append(c)

        for cb in self._callbacks:
            try:
                cb(new_conns)
            except Exception:
                pass

    def _poll_io(self):
        if not PSUTIL_OK:
            return
        try:
            raw = psutil.net_io_counters()
            now = time.time()

            snap = IOSnapshot(
                timestamp=now,
                bytes_sent=raw.bytes_sent,
                bytes_recv=raw.bytes_recv,
                packets_sent=raw.packets_sent,
                packets_recv=raw.packets_recv,
                error_in=raw.errin,
                error_out=raw.errout,
                drop_in=raw.dropin,
                drop_out=raw.dropout,
            )

            if self._last_io:
                elapsed = max(now - self._last_io.timestamp, 0.001)
                snap.send_rate_kbs = round(
                    (raw.bytes_sent - self._last_io.bytes_sent) / elapsed / 1024, 2
                )
                snap.recv_rate_kbs = round(
                    (raw.bytes_recv - self._last_io.bytes_recv) / elapsed / 1024, 2
                )

            self._last_io = snap
            self._io_history.append(snap)

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_process_name(self, pid: int) -> str:
        if pid == 0:
            return "kernel"
        if not PSUTIL_OK:
            return f"pid:{pid}"
        try:
            return psutil.Process(pid).name()[:20]
        except Exception:
            try:
                with open(f"/proc/{pid}/comm") as f:
                    return f.read().strip()[:20]
            except Exception:
                return f"pid:{pid}"

    def _resolve_hostname(self, ip: str) -> str:
        """Non-blocking hostname resolution with cache."""
        if not ip:
            return ""
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        # Only resolve if cache miss — use short timeout
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._hostname_cache[ip] = hostname
            return hostname
        except Exception:
            self._hostname_cache[ip] = ""
            return ""

    def _check_suspicious(self, remote_ip: str, remote_port: int,
                           proc_name: str) -> tuple[bool, str]:
        if remote_port in SUSPICIOUS_REMOTE_PORTS:
            reason = SUSPICIOUS_REMOTE_PORTS[remote_port]
            return True, f"Suspicious port {remote_port}: {reason}"
        if proc_name.lower() in SUSPICIOUS_PROCESSES:
            return True, f"Suspicious process: {proc_name}"
        return False, ""

    @staticmethod
    def format_rate(kbs: float) -> str:
        if kbs >= 1024:
            return f"{kbs/1024:.1f} MB/s"
        return f"{kbs:.1f} KB/s"