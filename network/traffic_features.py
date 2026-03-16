"""
network/traffic_features.py

Extracts numerical feature vectors from a time-window of network
metadata for AI anomaly detection.

Design: Window-based (10–30s snapshots), metadata only — no payloads.
CPU cost: Very low (pure Python arithmetic, no I/O per packet).

Feature vector (10 dimensions):
  [0]  connections_per_minute
  [1]  unique_destination_ips
  [2]  unique_destination_ports
  [3]  dns_request_rate      (requests/min)
  [4]  avg_packet_size       (bytes)
  [5]  tcp_ratio             (0.0–1.0)
  [6]  udp_ratio             (0.0–1.0)
  [7]  https_ratio           (0.0–1.0)
  [8]  port_entropy          (Shannon entropy of dst ports)
  [9]  destination_entropy   (Shannon entropy of dst IPs)
"""

import math
import time
from collections import deque, Counter
from dataclasses import dataclass, field
from typing import Optional


FEATURE_NAMES = [
    "connections_per_minute",
    "unique_destination_ips",
    "unique_destination_ports",
    "dns_request_rate",
    "avg_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "https_ratio",
    "port_entropy",
    "destination_entropy",
]

FEATURE_DIM = len(FEATURE_NAMES)   # 10


# ---------------------------------------------------------------------------
# Single observation recorded per connection/packet event
# ---------------------------------------------------------------------------

@dataclass
class TrafficObservation:
    timestamp: float
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "TCP"   # TCP / UDP / DNS / HTTP / HTTPS
    size: int = 0
    dns_query: str = ""
    is_tracker: bool = False


# ---------------------------------------------------------------------------
# Feature window
# ---------------------------------------------------------------------------

class TrafficFeatureWindow:
    """
    Maintains a rolling time-window of TrafficObservations and
    extracts a fixed-length feature vector on demand.

    Thread-safe for single-writer / single-reader usage.
    """

    def __init__(self, window_secs: float = 30.0, max_obs: int = 2000):
        self.window_secs = window_secs
        self._obs: deque = deque(maxlen=max_obs)
        self._dns_times: deque = deque(maxlen=500)

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def add(self, obs: TrafficObservation):
        self._obs.append(obs)
        if obs.protocol == "DNS" or obs.dns_query:
            self._dns_times.append(obs.timestamp)

    def add_from_connection(self, conn) -> TrafficObservation:
        """Convenience: build observation from PacketMetadata ConnectionMeta."""
        obs = TrafficObservation(
            timestamp=time.time(),
            src_ip=getattr(conn, "local_ip", ""),
            dst_ip=getattr(conn, "remote_ip", ""),
            dst_port=getattr(conn, "remote_port", 0),
            protocol=getattr(conn, "protocol", "TCP"),
            size=0,
            is_tracker=getattr(conn, "is_tracker", False),
        )
        self.add(obs)
        return obs

    def add_from_packet(self, pkt) -> TrafficObservation:
        """Convenience: build observation from PacketRecord."""
        obs = TrafficObservation(
            timestamp=getattr(pkt, "timestamp", time.time()),
            src_ip=getattr(pkt, "src_ip", ""),
            dst_ip=getattr(pkt, "dst_ip", ""),
            dst_port=getattr(pkt, "dst_port", 0),
            protocol=getattr(pkt, "protocol", "TCP"),
            size=getattr(pkt, "size", 0),
            dns_query=getattr(pkt, "dns_query", ""),
        )
        self.add(obs)
        return obs

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def extract(self) -> Optional[list[float]]:
        """
        Return a 10-dimensional feature vector for the current window.
        Returns None if too few observations exist (<5).
        """
        now = time.time()
        cutoff = now - self.window_secs
        window = [o for o in self._obs if o.timestamp >= cutoff]

        if len(window) < 5:
            return None

        elapsed_mins = max(self.window_secs / 60.0, 0.01)
        n = len(window)

        # Connections per minute
        conn_pm = n / elapsed_mins

        # Unique destinations
        dst_ips = [o.dst_ip for o in window if o.dst_ip]
        dst_ports = [o.dst_port for o in window if o.dst_port > 0]
        unique_ips = len(set(dst_ips))
        unique_ports = len(set(dst_ports))

        # DNS rate
        dns_cutoff = now - self.window_secs
        dns_recent = [t for t in self._dns_times if t >= dns_cutoff]
        dns_rate = len(dns_recent) / elapsed_mins

        # Average packet size
        sizes = [o.size for o in window if o.size > 0]
        avg_size = sum(sizes) / len(sizes) if sizes else 0.0

        # Protocol ratios
        proto_counts = Counter(o.protocol.upper() for o in window)
        total = max(n, 1)
        tcp_ratio   = proto_counts.get("TCP", 0) / total
        udp_ratio   = proto_counts.get("UDP", 0) / total
        https_ratio = proto_counts.get("HTTPS", 0) / total

        # Shannon entropy helpers
        port_entropy = _shannon_entropy(dst_ports)
        ip_entropy   = _shannon_entropy(dst_ips)

        return [
            round(conn_pm, 3),
            float(unique_ips),
            float(unique_ports),
            round(dns_rate, 3),
            round(avg_size, 1),
            round(tcp_ratio, 4),
            round(udp_ratio, 4),
            round(https_ratio, 4),
            round(port_entropy, 4),
            round(ip_entropy, 4),
        ]

    def extract_named(self) -> dict[str, float]:
        """Return feature vector as a named dict."""
        vec = self.extract()
        if vec is None:
            return {}
        return dict(zip(FEATURE_NAMES, vec))

    def observation_count(self) -> int:
        now = time.time()
        cutoff = now - self.window_secs
        return sum(1 for o in self._obs if o.timestamp >= cutoff)

    def clear(self):
        self._obs.clear()
        self._dns_times.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(values: list) -> float:
    """Compute Shannon entropy of a list of values."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


@dataclass
class FeatureStats:
    """Rolling min/max/mean for normalisation across windows."""
    n: int = 0
    means: list = field(default_factory=lambda: [0.0] * FEATURE_DIM)
    m2s:   list = field(default_factory=lambda: [0.0] * FEATURE_DIM)
    mins:  list = field(default_factory=lambda: [float("inf")] * FEATURE_DIM)
    maxs:  list = field(default_factory=lambda: [float("-inf")] * FEATURE_DIM)

    def update(self, vec: list[float]):
        """Welford online mean/variance update."""
        self.n += 1
        for i, x in enumerate(vec):
            delta = x - self.means[i]
            self.means[i] += delta / self.n
            delta2 = x - self.means[i]
            self.m2s[i] += delta * delta2
            self.mins[i] = min(self.mins[i], x)
            self.maxs[i] = max(self.maxs[i], x)

    def std(self, i: int) -> float:
        if self.n < 2:
            return 1.0
        return math.sqrt(self.m2s[i] / (self.n - 1))

    def zscore(self, vec: list[float]) -> list[float]:
        """Standardise a vector using running mean/std."""
        result = []
        for i, x in enumerate(vec):
            std = self.std(i)
            result.append((x - self.means[i]) / max(std, 1e-9))
        return result