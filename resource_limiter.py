"""
resource_limiter.py

DSRP Resource Governor — CPU and RAM adaptive throttling.
Designed for mid-range Android ARM devices in Termux.

Strategy:
  - Background thread polls CPU/RAM every N seconds via psutil
  - Publishes current pressure level: NORMAL / THROTTLE / SKIP / CRITICAL
  - Modules check pressure before heavy work and back off accordingly
  - No kernel-level resource limits (no root needed)

Usage:
    from resource_limiter import limiter, ResourceLevel

    # Simple guard before heavy work
    if limiter.ok_to_run("wifi_scan"):
        mapper.scan_now()

    # Decorator
    @limiter.guard(task="graph_render")
    def expensive_function():
        ...

    # Context manager
    with limiter.throttle_context("ml_inference"):
        model.train()

    # Check level directly
    level = limiter.level
    if level >= ResourceLevel.THROTTLE:
        time.sleep(limiter.suggested_sleep)
"""

from __future__ import annotations

import time
import threading
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Callable, Optional
from functools import wraps

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


# ─────────────────────────────────────────────────────────────────────────────
# Pressure levels
# ─────────────────────────────────────────────────────────────────────────────

class ResourceLevel(IntEnum):
    NORMAL   = 0   # All systems go
    THROTTLE = 1   # Slow down background work (increase sleep intervals)
    SKIP     = 2   # Skip non-critical tasks this cycle
    CRITICAL = 3   # Emergency: clear caches, skip everything non-essential


LEVEL_LABELS = {
    ResourceLevel.NORMAL:   "NORMAL",
    ResourceLevel.THROTTLE: "THROTTLE",
    ResourceLevel.SKIP:     "SKIP",
    ResourceLevel.CRITICAL: "CRITICAL",
}

LEVEL_COLORS = {
    ResourceLevel.NORMAL:   "#3FB950",
    ResourceLevel.THROTTLE: "#F0B429",
    ResourceLevel.SKIP:     "#FF7B72",
    ResourceLevel.CRITICAL: "bold #FF7B72",
}


# ─────────────────────────────────────────────────────────────────────────────
# Task priority — which tasks run under which pressure levels
# ─────────────────────────────────────────────────────────────────────────────

# Task name → minimum level at which it should be skipped
# (task runs if current level < skip_at_level)
TASK_PRIORITIES: dict[str, ResourceLevel] = {
    # Always run (critical path)
    "ids_rule_eval":     ResourceLevel.CRITICAL,
    "dns_monitor_poll":  ResourceLevel.CRITICAL,
    "response_engine":   ResourceLevel.CRITICAL,
    "incident_log":      ResourceLevel.CRITICAL,
    "blocker_check":     ResourceLevel.CRITICAL,

    # Run unless heavily throttled
    "connection_poll":   ResourceLevel.SKIP,
    "anomaly_analysis":  ResourceLevel.SKIP,
    "reputation_check":  ResourceLevel.SKIP,
    "feature_extract":   ResourceLevel.SKIP,

    # Skip under any pressure
    "wifi_scan":         ResourceLevel.THROTTLE,
    "graph_rebuild":     ResourceLevel.THROTTLE,
    "ml_retrain":        ResourceLevel.THROTTLE,
    "apk_analysis":      ResourceLevel.THROTTLE,
    "ioc_feed_update":   ResourceLevel.THROTTLE,
    "report_generation": ResourceLevel.THROTTLE,
}

# How much extra sleep to add between iterations at each level (seconds)
THROTTLE_SLEEP: dict[ResourceLevel, float] = {
    ResourceLevel.NORMAL:   0.0,
    ResourceLevel.THROTTLE: 5.0,
    ResourceLevel.SKIP:     15.0,
    ResourceLevel.CRITICAL: 30.0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Snapshot
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ResourceSnapshot:
    timestamp: float
    cpu_percent: float
    ram_used_mb: float
    ram_total_mb: float
    ram_percent: float
    level: ResourceLevel
    tasks_skipped: int = 0

    @property
    def ram_available_mb(self) -> float:
        return self.ram_total_mb - self.ram_used_mb

    @property
    def label(self) -> str:
        return LEVEL_LABELS[self.level]


# ─────────────────────────────────────────────────────────────────────────────
# Resource Governor
# ─────────────────────────────────────────────────────────────────────────────

class ResourceLimiter:
    """
    Background CPU/RAM monitor that provides pressure-based throttling
    to all DSRP modules via a simple API.
    """

    def __init__(self,
                 cpu_throttle: int  = 75,
                 cpu_skip: int      = 90,
                 ram_throttle_mb: int = 400,
                 ram_critical_mb: int = 600,
                 monitor_interval: int = 10,
                 adaptive: bool    = True):
        self.cpu_throttle    = cpu_throttle
        self.cpu_skip        = cpu_skip
        self.ram_throttle_mb = ram_throttle_mb
        self.ram_critical_mb = ram_critical_mb
        self.monitor_interval = monitor_interval
        self.adaptive        = adaptive

        self._level: ResourceLevel = ResourceLevel.NORMAL
        self._last_snapshot: Optional[ResourceSnapshot] = None
        self._lock = threading.RLock()

        self._tasks_skipped = 0
        self._total_checks  = 0

        # History for dashboard sparkline (last 60 readings)
        self._cpu_history:  list[float] = []
        self._ram_history:  list[float] = []
        self._level_history: list[int] = []

        # Callbacks: fn(ResourceSnapshot) on level change
        self._level_change_callbacks: list[Callable] = []

        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Start monitoring immediately
        self.start()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="resource-governor",
        )
        self._thread.start()

    def stop(self):
        self._running = False

    # ------------------------------------------------------------------
    # Core decision API
    # ------------------------------------------------------------------

    @property
    def level(self) -> ResourceLevel:
        with self._lock:
            return self._level

    @property
    def is_normal(self) -> bool:
        return self._level == ResourceLevel.NORMAL

    @property
    def suggested_sleep(self) -> float:
        """Additional sleep seconds to insert between iterations."""
        return THROTTLE_SLEEP.get(self._level, 0.0)

    def ok_to_run(self, task: str = "") -> bool:
        """
        Returns True if it's safe to run this task now.
        Always returns True if psutil unavailable.
        """
        if not PSUTIL_OK:
            return True

        self._total_checks += 1
        current_level = self.level

        # Look up task priority — default: skip at SKIP level
        skip_at = TASK_PRIORITIES.get(task, ResourceLevel.SKIP)

        if current_level >= skip_at:
            self._tasks_skipped += 1
            return False
        return True

    def wait_until_ok(self, task: str = "",
                       timeout: float = 60.0) -> bool:
        """
        Block until it's ok to run the task, or timeout expires.
        Returns True if cleared, False if timed out.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.ok_to_run(task):
                return True
            time.sleep(min(self.suggested_sleep + 1, 10))
        return False

    def guard(self, task: str = ""):
        """
        Decorator — skips the function body if resources are constrained.

        @limiter.guard(task="wifi_scan")
        def scan():
            ...
        """
        def decorator(fn: Callable):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if not self.ok_to_run(task):
                    return None
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def throttle_context(self, task: str = ""):
        """
        Context manager — adds adaptive sleep after the block completes.

        with limiter.throttle_context("ml_training"):
            model.train()
        """
        return _ThrottleContext(self, task)

    def add_level_change_callback(self, fn: Callable):
        """Called with ResourceSnapshot whenever pressure level changes."""
        self._level_change_callbacks.append(fn)

    # ------------------------------------------------------------------
    # Data access
    # ------------------------------------------------------------------

    def get_snapshot(self) -> Optional[ResourceSnapshot]:
        with self._lock:
            return self._last_snapshot

    def get_stats(self) -> dict:
        snap = self.get_snapshot()
        return {
            "level": LEVEL_LABELS.get(self._level, "?"),
            "cpu_percent": snap.cpu_percent if snap else 0,
            "ram_used_mb": snap.ram_used_mb if snap else 0,
            "ram_percent": snap.ram_percent if snap else 0,
            "tasks_skipped": self._tasks_skipped,
            "total_checks": self._total_checks,
            "skip_rate": round(
                self._tasks_skipped / max(self._total_checks, 1), 3),
        }

    def get_cpu_history(self) -> list[float]:
        with self._lock:
            return list(self._cpu_history)

    def get_ram_history(self) -> list[float]:
        with self._lock:
            return list(self._ram_history)

    def reconfigure(self,
                     cpu_throttle: int = None,
                     cpu_skip: int = None,
                     ram_throttle_mb: int = None,
                     ram_critical_mb: int = None):
        """Update thresholds at runtime."""
        if cpu_throttle is not None:
            self.cpu_throttle = max(30, min(95, cpu_throttle))
        if cpu_skip is not None:
            self.cpu_skip = max(self.cpu_throttle + 5, min(99, cpu_skip))
        if ram_throttle_mb is not None:
            self.ram_throttle_mb = max(100, ram_throttle_mb)
        if ram_critical_mb is not None:
            self.ram_critical_mb = max(self.ram_throttle_mb + 50, ram_critical_mb)

    # ------------------------------------------------------------------
    # Monitor loop
    # ------------------------------------------------------------------

    def _monitor_loop(self):
        while self._running:
            try:
                self._take_snapshot()
            except Exception:
                pass
            time.sleep(self.monitor_interval)

    def _take_snapshot(self):
        if not PSUTIL_OK:
            return

        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        ram_used = mem.used / 1024 / 1024
        ram_total = mem.total / 1024 / 1024
        ram_pct = mem.percent

        # Determine pressure level
        new_level = ResourceLevel.NORMAL

        if cpu >= self.cpu_skip or ram_used >= self.ram_critical_mb:
            new_level = ResourceLevel.CRITICAL
        elif cpu >= self.cpu_throttle or ram_used >= self.ram_throttle_mb:
            new_level = ResourceLevel.THROTTLE
        elif cpu >= self.cpu_throttle * 0.85:
            # Approaching throttle — pre-emptively slow down
            new_level = ResourceLevel.THROTTLE if self.adaptive else ResourceLevel.NORMAL

        snap = ResourceSnapshot(
            timestamp=time.time(),
            cpu_percent=round(cpu, 1),
            ram_used_mb=round(ram_used, 1),
            ram_total_mb=round(ram_total, 1),
            ram_percent=round(ram_pct, 1),
            level=new_level,
            tasks_skipped=self._tasks_skipped,
        )

        with self._lock:
            old_level = self._level
            self._level = new_level
            self._last_snapshot = snap

            # History (max 60 samples)
            self._cpu_history.append(cpu)
            self._ram_history.append(ram_used)
            self._level_history.append(new_level.value)
            if len(self._cpu_history) > 60:
                self._cpu_history.pop(0)
                self._ram_history.pop(0)
                self._level_history.pop(0)

        # Fire callbacks on level change
        if new_level != old_level:
            for cb in self._level_change_callbacks:
                try:
                    cb(snap)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Cache pruning (called when RAM is critical)
    # ------------------------------------------------------------------

    def suggest_cache_prune(self) -> bool:
        """Returns True if caches should be pruned now."""
        return self._level >= ResourceLevel.CRITICAL


# ─────────────────────────────────────────────────────────────────────────────
# Context manager helper
# ─────────────────────────────────────────────────────────────────────────────

class _ThrottleContext:
    def __init__(self, limiter: ResourceLimiter, task: str):
        self._limiter = limiter
        self._task = task
        self._skipped = False

    def __enter__(self):
        self._skipped = not self._limiter.ok_to_run(self._task)
        return self

    def __exit__(self, *args):
        if not self._skipped:
            sleep_time = self._limiter.suggested_sleep
            if sleep_time > 0:
                time.sleep(sleep_time)

    @property
    def skipped(self) -> bool:
        return self._skipped


# ─────────────────────────────────────────────────────────────────────────────
# Global singleton — configure once from config, use everywhere
# ─────────────────────────────────────────────────────────────────────────────

def _build_limiter() -> ResourceLimiter:
    try:
        from config import cfg
        return ResourceLimiter(
            cpu_throttle   = cfg.resources.cpu_throttle_threshold,
            cpu_skip       = cfg.resources.cpu_skip_threshold,
            ram_throttle_mb= cfg.resources.ram_throttle_mb,
            ram_critical_mb= cfg.resources.ram_critical_mb,
            monitor_interval=cfg.resources.monitor_interval_secs,
            adaptive       = cfg.resources.adaptive_throttling,
        )
    except Exception:
        return ResourceLimiter()


limiter: ResourceLimiter = _build_limiter()