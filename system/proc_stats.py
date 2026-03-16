"""
system/proc_stats.py

Lightweight system stats reader using /proc filesystem directly.
Works in Termux WITHOUT psutil installed.

Fallback chain:
  1. /proc/stat          → CPU usage
  2. /proc/meminfo       → RAM usage
  3. /proc/net/dev       → Network throughput
  4. psutil              → if available (more accurate)
"""

import os
import time
import threading
from dataclasses import dataclass, field
from typing import Optional

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False


@dataclass
class SystemStats:
    cpu_percent: float = 0.0
    ram_used_mb: float = 0.0
    ram_total_mb: float = 0.0
    ram_percent: float = 0.0
    net_sent_rate: float = 0.0   # bytes/sec
    net_recv_rate: float = 0.0
    battery_percent: Optional[float] = None
    timestamp: float = field(default_factory=time.time)


class ProcStatsReader:
    """
    Reads system stats from /proc without psutil.
    Falls back to psutil if available.
    """

    def __init__(self, interval: float = 3.0):
        self.interval = interval
        self._last: Optional[SystemStats] = None
        self._lock = threading.Lock()

        # For CPU delta calculation
        self._prev_cpu_idle: float = 0.0
        self._prev_cpu_total: float = 0.0

        # For network delta calculation
        self._prev_net_sent: int = 0
        self._prev_net_recv: int = 0
        self._prev_net_time: float = 0.0

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        # Prime the delta counters
        self._read_cpu_raw()
        self._read_net_raw()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="proc-stats")
        self._thread.start()

    def stop(self):
        self._running = False

    def get(self) -> SystemStats:
        """Return latest stats snapshot."""
        with self._lock:
            if self._last:
                return self._last
        # First call — read synchronously
        return self._read_all()

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    def _loop(self):
        while self._running:
            try:
                stats = self._read_all()
                with self._lock:
                    self._last = stats
            except Exception:
                pass
            time.sleep(self.interval)

    def _read_all(self) -> SystemStats:
        if _PSUTIL:
            return self._read_psutil()
        return self._read_proc()

    # ------------------------------------------------------------------
    # psutil path (accurate)
    # ------------------------------------------------------------------

    def _read_psutil(self) -> SystemStats:
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            net = psutil.net_io_counters()
            now = time.time()

            elapsed = max(now - self._prev_net_time, 0.001) if self._prev_net_time else 1.0
            sent_rate = max(0, (net.bytes_sent - self._prev_net_sent) / elapsed)
            recv_rate = max(0, (net.bytes_recv - self._prev_net_recv) / elapsed)

            self._prev_net_sent = net.bytes_sent
            self._prev_net_recv = net.bytes_recv
            self._prev_net_time = now

            battery = None
            try:
                b = psutil.sensors_battery()
                if b:
                    battery = round(b.percent, 1)
            except Exception:
                pass

            return SystemStats(
                cpu_percent=round(cpu, 1),
                ram_used_mb=round(mem.used / 1024 / 1024, 1),
                ram_total_mb=round(mem.total / 1024 / 1024, 1),
                ram_percent=round(mem.percent, 1),
                net_sent_rate=round(sent_rate, 1),
                net_recv_rate=round(recv_rate, 1),
                battery_percent=battery,
            )
        except Exception:
            return self._read_proc()

    # ------------------------------------------------------------------
    # /proc path (no root, no psutil)
    # ------------------------------------------------------------------

    def _read_proc(self) -> SystemStats:
        stats = SystemStats()
        stats.cpu_percent = self._read_cpu_percent()
        stats.ram_used_mb, stats.ram_total_mb, stats.ram_percent = self._read_mem()
        stats.net_sent_rate, stats.net_recv_rate = self._read_net_rate()
        stats.battery_percent = self._read_battery()
        return stats

    def _read_cpu_raw(self) -> tuple[float, float]:
        """Read /proc/stat and return (idle, total)."""
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            parts = line.split()
            if parts[0] != "cpu":
                return 0.0, 0.0
            # user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
            values = [float(x) for x in parts[1:]]
            idle  = values[3] + (values[4] if len(values) > 4 else 0)
            total = sum(values)
            return idle, total
        except Exception:
            return 0.0, 0.0

    def _read_cpu_percent(self) -> float:
        idle, total = self._read_cpu_raw()
        if self._prev_cpu_total == 0:
            self._prev_cpu_idle  = idle
            self._prev_cpu_total = total
            return 0.0

        delta_idle  = idle  - self._prev_cpu_idle
        delta_total = total - self._prev_cpu_total

        self._prev_cpu_idle  = idle
        self._prev_cpu_total = total

        if delta_total <= 0:
            return 0.0
        return round((1.0 - delta_idle / delta_total) * 100.0, 1)

    def _read_mem(self) -> tuple[float, float, float]:
        """Read /proc/meminfo and return (used_mb, total_mb, percent)."""
        try:
            info: dict[str, int] = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].rstrip(":")
                        val = int(parts[1])   # kB
                        info[key] = val

            total     = info.get("MemTotal", 0)
            free      = info.get("MemFree", 0)
            buffers   = info.get("Buffers", 0)
            cached    = info.get("Cached", 0)
            sreclm    = info.get("SReclaimable", 0)
            available = info.get("MemAvailable",
                                 free + buffers + cached + sreclm)

            used    = total - available
            used_mb = round(used  / 1024, 1)
            tot_mb  = round(total / 1024, 1)
            pct     = round(used / total * 100, 1) if total > 0 else 0.0
            return used_mb, tot_mb, pct
        except Exception:
            return 0.0, 0.0, 0.0

    def _read_net_raw(self) -> tuple[int, int]:
        """Read /proc/net/dev and return (total_sent, total_recv) bytes."""
        try:
            sent_total = recv_total = 0
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:   # skip 2-line header
                    parts = line.split()
                    if not parts:
                        continue
                    iface = parts[0].rstrip(":")
                    # Skip loopback
                    if iface in ("lo",):
                        continue
                    # /proc/net/dev columns:
                    # recv: bytes packets errs drop ... (cols 1-8)
                    # send: bytes packets errs drop ... (cols 9-16)
                    recv_total += int(parts[1])
                    sent_total += int(parts[9])
            return sent_total, recv_total
        except Exception:
            return 0, 0

    def _read_net_rate(self) -> tuple[float, float]:
        """Return (sent_rate_bps, recv_rate_bps) since last call."""
        now = time.time()
        sent, recv = self._read_net_raw()

        if self._prev_net_time == 0:
            self._prev_net_sent = sent
            self._prev_net_recv = recv
            self._prev_net_time = now
            return 0.0, 0.0

        elapsed = max(now - self._prev_net_time, 0.001)
        sent_rate = max(0.0, (sent - self._prev_net_sent) / elapsed)
        recv_rate = max(0.0, (recv - self._prev_net_recv) / elapsed)

        self._prev_net_sent = sent
        self._prev_net_recv = recv
        self._prev_net_time = now

        return round(sent_rate, 1), round(recv_rate, 1)

    def _read_battery(self) -> Optional[float]:
        """Read battery from Android sysfs or /proc."""
        paths = [
            "/sys/class/power_supply/battery/capacity",
            "/sys/class/power_supply/Battery/capacity",
        ]
        for path in paths:
            try:
                with open(path) as f:
                    return float(f.read().strip())
            except Exception:
                pass
        return None

    @staticmethod
    def fmt_bytes(bps: float) -> str:
        if bps >= 1_000_000:
            return f"{bps/1_000_000:.1f}MB/s"
        elif bps >= 1_000:
            return f"{bps/1_000:.0f}KB/s"
        elif bps > 0:
            return f"{bps:.0f}B/s"
        return "0B/s"


# Global singleton
_reader: Optional[ProcStatsReader] = None

def get_stats_reader() -> ProcStatsReader:
    global _reader
    if _reader is None:
        _reader = ProcStatsReader(interval=3.0)
        _reader.start()
    return _reader

def read_stats() -> SystemStats:
    """One-shot read — for use outside the background reader."""
    r = ProcStatsReader()
    return r._read_all()