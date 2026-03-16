"""
network/connection_tracker.py

Maps active connections to applications.
Output format: app_name -> remote_ip:port -> domain

Uses psutil.net_connections() — lightweight, no root needed.
CPU cost: Low (~1–2%)
Poll interval: 10s (configurable)
"""

import time
import socket
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AppConnection:
    app_name: str
    pid: int
    remote_ip: str
    remote_port: int
    remote_hostname: str = ""
    protocol: str = "TCP"
    status: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    is_tracker: bool = False
    tracker_name: str = ""
    is_suspicious: bool = False   # compatibility with PacketMetadataCollector
    flag_reason: str = ""

    @property
    def process_name(self) -> str:
        """Alias for app_name — compatibility with PacketMetadataCollector."""
        return self.app_name

    @property
    def remote_display(self) -> str:
        host = self.remote_hostname or self.remote_ip
        return f"{host}:{self.remote_port}"

    def ascii_line(self, indent: int = 4) -> str:
        tracker_flag = f"  ← TRACKER: {self.tracker_name}" if self.is_tracker else ""
        return f"{' ' * indent}{self.remote_display}{tracker_flag}"


@dataclass
class AppConnectionGroup:
    """All connections for a single app."""
    app_name: str
    pid: int
    connections: list = field(default_factory=list)
    total_remotes: int = 0
    tracker_count: int = 0

    def ascii_tree(self) -> str:
        """Render as ASCII tree."""
        lines = [f"[{self.app_name}]"]
        conns = sorted(self.connections, key=lambda c: c.remote_port)
        for i, conn in enumerate(conns):
            is_last = (i == len(conns) - 1)
            prefix = "└─" if is_last else "├─"
            tracker_flag = f"  ⚠ {conn.tracker_name}" if conn.is_tracker else ""
            host = conn.remote_hostname or conn.remote_ip
            lines.append(f"  {prefix} {host}:{conn.remote_port}{tracker_flag}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Connection Tracker
# ---------------------------------------------------------------------------

class ConnectionTracker:
    """
    Tracks network connections per-application.
    Produces ASCII tree visualizations and structured data.
    
    Architecture:
    - Background thread polls psutil every `poll_interval` seconds
    - Maintains a live map: app_name -> [AppConnection]
    - Tracker domain detection via injected db
    - Deduplicates by (pid, remote_ip, remote_port)
    """

    def __init__(self,
                 poll_interval: float = 10.0,
                 tracker_db: dict = None,
                 resolve_hostnames: bool = True):
        self.poll_interval = poll_interval
        self._tracker_db: dict[str, str] = tracker_db or {}
        self.resolve_hostnames = resolve_hostnames

        # Live connection map: app_name -> list[AppConnection]
        self._connections: dict[str, list[AppConnection]] = {}
        self._lock = threading.Lock()

        # History: deque of (timestamp, app_name, remote)
        self._history: deque = deque(maxlen=1000)

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._hostname_cache: dict[str, str] = {}
        self._last_poll_time: float = 0

        self._stats = {
            "total_polls": 0,
            "active_apps": 0,
            "active_connections": 0,
            "tracker_connections": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_tracker_db(self, db: dict):
        self._tracker_db = db

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="conn-tracker"
        )
        self._thread.start()

    def stop(self):
        self._running = False

    def get_connection_groups(self) -> list[AppConnectionGroup]:
        """Return all app connection groups, sorted by connection count."""
        with self._lock:
            groups = []
            for app, conns in self._connections.items():
                if not conns:
                    continue
                pid = conns[0].pid if conns else 0
                g = AppConnectionGroup(
                    app_name=app,
                    pid=pid,
                    connections=list(conns),
                    total_remotes=len(conns),
                    tracker_count=sum(1 for c in conns if c.is_tracker),
                )
                groups.append(g)
        return sorted(groups, key=lambda g: g.total_remotes, reverse=True)

    def get_ascii_tree(self, max_apps: int = 15) -> str:
        """Render full connection map as ASCII tree."""
        groups = self.get_connection_groups()[:max_apps]
        if not groups:
            return "(no active connections)"

        lines = ["Android Device"]
        for i, group in enumerate(groups):
            is_last = (i == len(groups) - 1)
            prefix = "└─" if is_last else "├─"
            tracker_note = f" [{group.tracker_count} trackers]" if group.tracker_count else ""
            lines.append(f" {prefix} {group.app_name}{tracker_note}")

            conns = sorted(group.connections, key=lambda c: c.remote_port)
            for j, conn in enumerate(conns[:6]):  # max 6 per app
                is_last_conn = (j == len(conns[:6]) - 1)
                tree_char = "   └─" if is_last_conn else "   ├─"
                if is_last:
                    tree_char = "    └─" if is_last_conn else "    ├─"
                host = (conn.remote_hostname or conn.remote_ip)[:30]
                tracker_flag = f" ⚠" if conn.is_tracker else ""
                lines.append(f" {tree_char} {host}:{conn.remote_port}{tracker_flag}")
            if len(conns) > 6:
                lines.append(f"      … +{len(conns)-6} more")

        return "\n".join(lines)

    def get_active_connections(self,
                               protocol: str = None,
                               suspicious_only: bool = False) -> list[AppConnection]:
        """
        Return a flat list of all active AppConnection objects.
        Compatible with PacketMetadataCollector.get_active_connections() signature
        so both can be used interchangeably in UI code.
        """
        result = []
        with self._lock:
            for conns in self._connections.values():
                result.extend(conns)
        if protocol:
            result = [c for c in result if c.protocol.upper() == protocol.upper()]
        if suspicious_only:
            result = [c for c in result if c.is_tracker or c.is_suspicious]
        return result

    def get_tracker_connections(self) -> list[AppConnection]:
        """Return all connections to tracker domains."""
        result = []
        with self._lock:
            for conns in self._connections.values():
                result.extend(c for c in conns if c.is_tracker)
        return sorted(result, key=lambda c: c.tracker_name)

    def get_remote_ip_list(self) -> list[str]:
        """Flat list of all unique remote IPs currently connected."""
        ips = set()
        with self._lock:
            for conns in self._connections.values():
                ips.update(c.remote_ip for c in conns if c.remote_ip)
        return sorted(ips)

    def get_stats(self) -> dict:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    def _poll_loop(self):
        while self._running:
            try:
                self._poll_once()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _poll_once(self):
        if not PSUTIL_OK:
            return

        now = time.time()
        self._last_poll_time = now

        new_map: dict[str, list[AppConnection]] = defaultdict(list)
        total_conns = 0
        tracker_conns = 0

        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return

        for conn in connections:
            if not conn.raddr:
                continue

            remote_ip   = conn.raddr.ip
            remote_port = conn.raddr.port
            pid         = conn.pid or 0
            protocol    = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            status      = conn.status or ""

            app_name = self._get_app_name(pid)
            hostname = self._resolve(remote_ip) if self.resolve_hostnames else ""
            is_tracker, tracker_name = self._check_tracker(hostname or remote_ip)

            ac = AppConnection(
                app_name=app_name,
                pid=pid,
                remote_ip=remote_ip,
                remote_port=remote_port,
                remote_hostname=hostname,
                protocol=protocol,
                status=status,
                first_seen=now,
                last_seen=now,
                is_tracker=is_tracker,
                tracker_name=tracker_name,
            )
            new_map[app_name].append(ac)
            self._history.append((now, app_name, ac.remote_display))
            total_conns += 1
            if is_tracker:
                tracker_conns += 1

        with self._lock:
            self._connections = dict(new_map)

        self._stats.update({
            "total_polls": self._stats["total_polls"] + 1,
            "active_apps": len(new_map),
            "active_connections": total_conns,
            "tracker_connections": tracker_conns,
            "last_poll": now,
        })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_app_name(self, pid: int) -> str:
        if pid == 0:
            return "kernel"
        try:
            with open(f"/proc/{pid}/comm") as f:
                return f.read().strip()[:25]
        except Exception:
            pass
        if PSUTIL_OK:
            try:
                return psutil.Process(pid).name()[:25]
            except Exception:
                pass
        return f"pid:{pid}"

    def _resolve(self, ip: str) -> str:
        if not ip:
            return ""
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._hostname_cache[ip] = hostname
            return hostname
        except Exception:
            self._hostname_cache[ip] = ""
            return ""

    def _check_tracker(self, host: str) -> tuple[bool, str]:
        if not host or not self._tracker_db:
            return False, ""
        host = host.lower().strip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self._tracker_db:
                return True, self._tracker_db[candidate]
        return False, ""