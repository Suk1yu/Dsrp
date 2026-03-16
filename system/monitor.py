"""
system/monitor.py
Real-time system resource monitor using psutil.
Tracks CPU, RAM, network throughput, and active processes.
"""

import time
import psutil
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SystemSnapshot:
    timestamp: float
    cpu_percent: float
    ram_used_mb: float
    ram_total_mb: float
    ram_percent: float
    net_bytes_sent: int
    net_bytes_recv: int
    net_send_rate: float  # bytes/sec
    net_recv_rate: float  # bytes/sec
    active_processes: list = field(default_factory=list)
    disk_percent: float = 0.0
    battery_percent: Optional[float] = None
    temperature: Optional[float] = None


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float
    ram_mb: float
    status: str
    connections: int = 0


class SystemMonitor:
    """
    Collects real-time system metrics using psutil.
    Maintains a history buffer for sparkline-style visualization.
    """

    def __init__(self, history_size: int = 60):
        self.history_size = history_size
        self._cpu_history: list[float] = []
        self._ram_history: list[float] = []
        self._net_send_history: list[float] = []
        self._net_recv_history: list[float] = []

        self._last_net_io = psutil.net_io_counters()
        self._last_time = time.time()

    def snapshot(self, top_processes: int = 10) -> SystemSnapshot:
        """Take a current system snapshot."""
        now = time.time()
        elapsed = max(now - self._last_time, 0.001)

        cpu = psutil.cpu_percent(interval=None)

        mem = psutil.virtual_memory()
        ram_used = mem.used / 1024 / 1024
        ram_total = mem.total / 1024 / 1024
        ram_pct = mem.percent

        net = psutil.net_io_counters()
        send_rate = max(0, (net.bytes_sent - self._last_net_io.bytes_sent) / elapsed)
        recv_rate = max(0, (net.bytes_recv - self._last_net_io.bytes_recv) / elapsed)
        self._last_net_io = net
        self._last_time = now

        # Disk
        disk_pct = 0.0
        try:
            disk_pct = psutil.disk_usage("/").percent
        except Exception:
            pass

        # Battery
        battery_pct = None
        try:
            batt = psutil.sensors_battery()
            if batt:
                battery_pct = batt.percent
        except Exception:
            pass

        # Temperature (Android)
        temperature = None
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    if entries:
                        temperature = entries[0].current
                        break
        except Exception:
            pass

        # Processes
        processes = self._get_top_processes(top_processes)

        snap = SystemSnapshot(
            timestamp=now,
            cpu_percent=round(cpu, 1),
            ram_used_mb=round(ram_used, 1),
            ram_total_mb=round(ram_total, 1),
            ram_percent=round(ram_pct, 1),
            net_bytes_sent=net.bytes_sent,
            net_bytes_recv=net.bytes_recv,
            net_send_rate=round(send_rate, 1),
            net_recv_rate=round(recv_rate, 1),
            active_processes=processes,
            disk_percent=round(disk_pct, 1),
            battery_percent=battery_pct,
            temperature=temperature,
        )

        # Update history
        self._update_history(snap)
        return snap

    def _get_top_processes(self, n: int) -> list[ProcessInfo]:
        procs = []
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "cpu_percent", "memory_info", "status", "connections"]
            ):
                try:
                    info = proc.info
                    mem_mb = (info.get("memory_info") or 0)
                    if hasattr(mem_mb, "rss"):
                        mem_mb = mem_mb.rss / 1024 / 1024
                    else:
                        mem_mb = 0.0

                    conns = 0
                    try:
                        conns = len(info.get("connections") or [])
                    except Exception:
                        pass

                    procs.append(ProcessInfo(
                        pid=info["pid"],
                        name=info.get("name", "unknown")[:20],
                        cpu_percent=round(info.get("cpu_percent", 0) or 0, 1),
                        ram_mb=round(mem_mb, 1),
                        status=info.get("status", ""),
                        connections=conns,
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

        return sorted(procs, key=lambda p: p.cpu_percent, reverse=True)[:n]

    def _update_history(self, snap: SystemSnapshot):
        def append(lst, val):
            lst.append(val)
            while len(lst) > self.history_size:
                lst.pop(0)

        append(self._cpu_history, snap.cpu_percent)
        append(self._ram_history, snap.ram_percent)
        append(self._net_send_history, snap.net_send_rate / 1024)  # KB/s
        append(self._net_recv_history, snap.net_recv_rate / 1024)

    def get_cpu_history(self) -> list[float]:
        return list(self._cpu_history)

    def get_ram_history(self) -> list[float]:
        return list(self._ram_history)

    def get_net_history(self) -> tuple[list[float], list[float]]:
        return list(self._net_send_history), list(self._net_recv_history)

    @staticmethod
    def format_bytes(b: float) -> str:
        if b >= 1_000_000:
            return f"{b/1_000_000:.1f} MB/s"
        elif b >= 1_000:
            return f"{b/1_000:.1f} KB/s"
        return f"{b:.0f} B/s"