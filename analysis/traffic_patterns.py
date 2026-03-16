"""
analysis/traffic_patterns.py

Traffic pattern analysis — frequency, timing, protocol distribution.
All analysis is on-demand batch processing, not real-time.

Provides:
  - hourly activity heatmap
  - protocol distribution pie data
  - connection burst detection
  - daily volume trends
"""

import time
import math
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HourlyBucket:
    hour: int              # 0–23
    connection_count: int = 0
    dns_count: int = 0
    tracker_count: int = 0
    unique_destinations: set = field(default_factory=set)

    @property
    def label(self) -> str:
        return f"{self.hour:02d}:00"


@dataclass
class ProtocolDistribution:
    tcp:   int = 0
    udp:   int = 0
    dns:   int = 0
    https: int = 0
    http:  int = 0
    other: int = 0

    def total(self) -> int:
        return self.tcp + self.udp + self.dns + self.https + self.http + self.other

    def as_dict(self) -> dict:
        t = max(self.total(), 1)
        return {
            "TCP":   self.tcp,
            "UDP":   self.udp,
            "DNS":   self.dns,
            "HTTPS": self.https,
            "HTTP":  self.http,
            "OTHER": self.other,
        }

    def as_pct_dict(self) -> dict:
        t = max(self.total(), 1)
        return {k: round(v / t * 100, 1)
                for k, v in self.as_dict().items()}


@dataclass
class BurstEvent:
    timestamp: float
    duration_secs: float
    peak_rate: float        # conns/sec during burst
    total_connections: int
    unique_destinations: int
    protocol: str = "mixed"


@dataclass
class TrafficPatternReport:
    generated_at: float
    total_events: int = 0
    hourly_buckets: list = field(default_factory=list)
    protocol_dist: ProtocolDistribution = field(
        default_factory=ProtocolDistribution)
    burst_events: list = field(default_factory=list)
    peak_hour: int = 0
    quiet_hours: list = field(default_factory=list)
    dominant_protocol: str = "HTTPS"
    avg_connections_per_min: float = 0.0
    tracker_ratio: float = 0.0


class TrafficPatternAnalyser:
    """
    Analyses temporal and protocol patterns in network traffic.
    Feed raw event dicts (same format as ConnectionAnalyser).
    """

    def __init__(self):
        self._events: list = []
        self._max_events = 5000

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest(self, event: dict):
        """Add a single traffic event dict."""
        self._events.append(event)
        if len(self._events) > self._max_events:
            self._events.pop(0)

    def ingest_batch(self, events: list):
        self._events.extend(events)
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

    def ingest_connections(self, connections: list):
        now = time.time()
        for conn in connections:
            self.ingest({
                "ts":       now,
                "protocol": getattr(conn, "protocol", "TCP"),
                "is_tracker": getattr(conn, "is_tracker", False),
                "remote":   getattr(conn, "remote_ip", ""),
                "port":     getattr(conn, "remote_port", 0),
            })

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyse(self, window_secs: float = 86400.0) -> TrafficPatternReport:
        """Produce a full traffic pattern report."""
        now = time.time()
        cutoff = now - window_secs
        events = [e for e in self._events if e.get("ts", 0) >= cutoff]

        report = TrafficPatternReport(
            generated_at=now,
            total_events=len(events),
        )

        if not events:
            return report

        # Protocol distribution
        proto_dist = ProtocolDistribution()
        for e in events:
            p = e.get("protocol", "").upper()
            if p == "TCP":    proto_dist.tcp   += 1
            elif p == "UDP":  proto_dist.udp   += 1
            elif p == "DNS":  proto_dist.dns   += 1
            elif p == "HTTPS":proto_dist.https += 1
            elif p == "HTTP": proto_dist.http  += 1
            else:             proto_dist.other += 1
        report.protocol_dist = proto_dist

        # Dominant protocol
        pdict = proto_dist.as_dict()
        report.dominant_protocol = max(pdict, key=pdict.get)

        # Hourly buckets
        buckets: dict[int, HourlyBucket] = {}
        for e in events:
            ts = e.get("ts", now)
            hour = int(time.localtime(ts).tm_hour)
            if hour not in buckets:
                buckets[hour] = HourlyBucket(hour=hour)
            b = buckets[hour]
            b.connection_count += 1
            if e.get("protocol", "").upper() == "DNS":
                b.dns_count += 1
            if e.get("is_tracker", False):
                b.tracker_count += 1
            remote = e.get("remote", "")
            if remote:
                b.unique_destinations.add(remote)

        report.hourly_buckets = sorted(buckets.values(), key=lambda b: b.hour)

        # Peak / quiet hours
        if buckets:
            report.peak_hour = max(buckets, key=lambda h: buckets[h].connection_count)
            sorted_hours = sorted(buckets.items(),
                                  key=lambda x: x[1].connection_count)
            report.quiet_hours = [h for h, _ in sorted_hours[:4]]

        # Avg connections per minute
        if window_secs > 0:
            report.avg_connections_per_min = round(
                len(events) / (window_secs / 60), 2
            )

        # Tracker ratio
        tracker_count = sum(1 for e in events if e.get("is_tracker", False))
        report.tracker_ratio = round(tracker_count / max(len(events), 1), 4)

        # Burst detection
        report.burst_events = self._detect_bursts(events)

        return report

    def _detect_bursts(self, events: list) -> list[BurstEvent]:
        """Detect short windows with unusually high connection rate."""
        if len(events) < 10:
            return []

        # 10-second sliding window
        window = 10.0
        burst_threshold = 5.0   # connections/sec to be a burst
        bursts = []

        times = sorted(e["ts"] for e in events)
        i = 0
        while i < len(times):
            # Count events in window starting at times[i]
            j = i
            while j < len(times) and times[j] - times[i] <= window:
                j += 1
            rate = (j - i) / window
            if rate >= burst_threshold and j - i >= 5:
                # Collect destinations
                dsts = set()
                proto_counter: Counter = Counter()
                for e in events:
                    if times[i] <= e.get("ts", 0) <= times[i] + window:
                        r = e.get("remote", "")
                        if r:
                            dsts.add(r)
                        proto_counter[e.get("protocol", "?")] += 1

                dom_proto = proto_counter.most_common(1)[0][0] \
                    if proto_counter else "mixed"

                bursts.append(BurstEvent(
                    timestamp=times[i],
                    duration_secs=window,
                    peak_rate=round(rate, 2),
                    total_connections=j - i,
                    unique_destinations=len(dsts),
                    protocol=dom_proto,
                ))
                i = j  # skip to after burst
            else:
                i += 1

        return bursts[:20]

    def get_ascii_heatmap(self, report: TrafficPatternReport) -> str:
        """Render an ASCII hourly heatmap."""
        if not report.hourly_buckets:
            return "(no data)"

        max_count = max(b.connection_count for b in report.hourly_buckets) or 1
        bar_width  = 30

        lines = ["Hourly Activity (last 24h):", ""]
        for b in report.hourly_buckets:
            filled = int(b.connection_count / max_count * bar_width)
            bar    = "█" * filled + "░" * (bar_width - filled)
            t_mark = "⚠" if b.tracker_count > 0 else " "
            lines.append(f"  {b.label}  {bar}  {b.connection_count:4d} {t_mark}")

        # Protocol summary
        pct = report.protocol_dist.as_pct_dict()
        lines.append("")
        lines.append("Protocol Distribution:")
        for proto, pct_val in sorted(pct.items(), key=lambda x: x[1], reverse=True):
            if pct_val > 0:
                bar = "▓" * int(pct_val / 4)
                lines.append(f"  {proto:<6} {bar} {pct_val:.0f}%")

        return "\n".join(lines)