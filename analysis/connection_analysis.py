"""
analysis/connection_analysis.py

Advanced connection pattern analysis.
Runs on-demand (not continuous) over a snapshot of connection history.

Produces:
  - top contacted domains / IPs
  - port frequency distribution
  - tracker vs clean ratio
  - connection frequency timeline
  - potential C2 candidates (low diversity, high frequency)
"""

import time
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DomainProfile:
    domain: str
    request_count: int = 0
    unique_apps: set = field(default_factory=set)
    ports_used: set = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_tracker: bool = False
    tracker_name: str = ""
    is_suspicious: bool = False
    suspicion_reason: str = ""

    @property
    def request_rate(self) -> float:
        """Requests per minute since first_seen."""
        elapsed = max((self.last_seen - self.first_seen) / 60.0, 0.01)
        return round(self.request_count / elapsed, 2)


@dataclass
class ConnectionReport:
    generated_at: float
    analysis_window_secs: float
    total_connections: int = 0
    unique_domains: int = 0
    unique_ips: int = 0
    unique_apps: int = 0
    tracker_domains: int = 0
    suspicious_domains: int = 0
    top_domains: list = field(default_factory=list)
    top_ips: list = field(default_factory=list)
    top_ports: list = field(default_factory=list)
    top_apps: list = field(default_factory=list)
    tracker_list: list = field(default_factory=list)
    c2_candidates: list = field(default_factory=list)
    port_entropy: float = 0.0
    destination_entropy: float = 0.0


@dataclass
class C2Candidate:
    remote: str
    app: str
    connection_count: int
    interval_mean: float = 0.0
    interval_std: float = 0.0
    jitter: float = 1.0
    reason: str = ""
    confidence: str = "LOW"   # LOW / MEDIUM / HIGH


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

class ConnectionAnalyser:
    """
    Analyses a collection of connection metadata snapshots.
    All analysis is batch / on-demand — call analyse() when needed.
    """

    def __init__(self, window_secs: float = 300.0):
        self.window_secs = window_secs
        self._connection_log: list = []          # list of dicts

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    def ingest_connections(self, connections: list):
        """Add a batch of ConnectionMeta objects to the log."""
        now = time.time()
        for conn in connections:
            self._connection_log.append({
                "ts":       now,
                "app":      getattr(conn, "process_name", "unknown") or "unknown",
                "remote_ip":  getattr(conn, "remote_ip", ""),
                "remote_host": getattr(conn, "remote_hostname", "") or \
                               getattr(conn, "remote_ip", ""),
                "remote_port": getattr(conn, "remote_port", 0),
                "protocol":    getattr(conn, "protocol", "TCP"),
                "is_tracker":  getattr(conn, "is_tracker", False),
                "tracker_name": getattr(conn, "tracker_name", ""),
            })

        # Prune old entries
        cutoff = now - self.window_secs * 2
        self._connection_log = [
            e for e in self._connection_log if e["ts"] >= cutoff
        ]

    def ingest_dns_stats(self, dns_stats: list):
        """Ingest from DNS monitor domain stats list."""
        now = time.time()
        for stat in dns_stats:
            for _ in range(min(stat.request_count, 20)):
                self._connection_log.append({
                    "ts":          stat.last_seen or now,
                    "app":         "dns",
                    "remote_ip":   "",
                    "remote_host": stat.domain,
                    "remote_port": 53,
                    "protocol":    "DNS",
                    "is_tracker":  stat.is_tracker,
                    "tracker_name": stat.tracker_name,
                })

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyse(self, window_secs: float = None) -> ConnectionReport:
        """Run full analysis on buffered connection data."""
        now = time.time()
        ws  = window_secs or self.window_secs
        cutoff = now - ws

        window = [e for e in self._connection_log if e["ts"] >= cutoff]
        if not window:
            return ConnectionReport(
                generated_at=now, analysis_window_secs=ws
            )

        report = ConnectionReport(
            generated_at=now,
            analysis_window_secs=ws,
            total_connections=len(window),
        )

        # Frequency counters
        domain_counts: Counter = Counter()
        ip_counts:     Counter = Counter()
        port_counts:   Counter = Counter()
        app_counts:    Counter = Counter()
        tracker_names: Counter = Counter()

        # Per-domain metadata
        domain_meta: dict[str, DomainProfile] = {}

        # Per-(app,remote) timestamps for beaconing detection
        flow_times: dict[tuple, list] = defaultdict(list)

        for entry in window:
            host  = entry["remote_host"]
            ip    = entry["remote_ip"]
            port  = entry["remote_port"]
            app   = entry["app"]
            is_t  = entry["is_tracker"]
            tname = entry["tracker_name"]
            ts    = entry["ts"]

            if host:
                domain_counts[host] += 1
                if host not in domain_meta:
                    domain_meta[host] = DomainProfile(
                        domain=host, first_seen=ts,
                        is_tracker=is_t, tracker_name=tname
                    )
                dm = domain_meta[host]
                dm.request_count += 1
                dm.last_seen = max(dm.last_seen, ts)
                dm.first_seen = min(dm.first_seen or ts, ts)
                dm.unique_apps.add(app)
                if port:
                    dm.ports_used.add(port)

            if ip:
                ip_counts[ip] += 1
            if port:
                port_counts[port] += 1
            if app:
                app_counts[app] += 1
            if is_t and tname:
                tracker_names[tname] += 1

            # Beaconing accumulation
            if host and app:
                flow_times[(app, host)].append(ts)

        # Populate report
        report.unique_domains = len(domain_counts)
        report.unique_ips     = len(ip_counts)
        report.unique_apps    = len(app_counts)
        report.tracker_domains = sum(1 for dm in domain_meta.values() if dm.is_tracker)

        report.top_domains = [
            {"domain": d, "count": c,
             "is_tracker": domain_meta.get(d, DomainProfile(d)).is_tracker,
             "tracker_name": domain_meta.get(d, DomainProfile(d)).tracker_name}
            for d, c in domain_counts.most_common(20)
        ]
        report.top_ips = [
            {"ip": ip, "count": c} for ip, c in ip_counts.most_common(15)
        ]
        report.top_ports = [
            {"port": p, "count": c,
             "service": _port_service(p)}
            for p, c in port_counts.most_common(15)
        ]
        report.top_apps = [
            {"app": a, "count": c} for a, c in app_counts.most_common(15)
        ]
        report.tracker_list = [
            {"name": n, "count": c} for n, c in tracker_names.most_common()
        ]

        # Entropy metrics
        report.port_entropy = _entropy(list(port_counts.values()))
        report.destination_entropy = _entropy(list(domain_counts.values()))

        # Beaconing / C2 candidates
        report.c2_candidates = self._detect_c2_candidates(flow_times)
        report.suspicious_domains = len(report.c2_candidates)

        return report

    def _detect_c2_candidates(self,
                               flow_times: dict) -> list[C2Candidate]:
        """Detect flows with suspiciously regular intervals."""
        candidates = []
        for (app, remote), times in flow_times.items():
            if len(times) < 6:
                continue
            times_sorted = sorted(times)
            intervals = [b - a for a, b in zip(times_sorted, times_sorted[1:])]
            if len(intervals) < 3:
                continue
            mean_i = sum(intervals) / len(intervals)
            if mean_i < 2.0:          # too fast to be beacon
                continue
            variance = sum((x - mean_i) ** 2 for x in intervals) / len(intervals)
            std_i = math.sqrt(variance)
            jitter = std_i / mean_i if mean_i > 0 else 1.0

            if jitter > 0.25:         # too irregular
                continue

            if jitter < 0.08:
                confidence = "HIGH"
            elif jitter < 0.15:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"

            candidates.append(C2Candidate(
                remote=remote,
                app=app,
                connection_count=len(times),
                interval_mean=round(mean_i, 2),
                interval_std=round(std_i, 2),
                jitter=round(jitter, 3),
                reason=(f"Regular {mean_i:.0f}s interval (±{std_i:.1f}s, "
                        f"jitter={jitter:.2f}) over {len(times)} connections"),
                confidence=confidence,
            ))

        return sorted(candidates,
                      key=lambda c: (c.confidence == "HIGH",
                                     c.confidence == "MEDIUM",
                                     c.connection_count),
                      reverse=True)[:10]

    def get_snapshot_count(self) -> int:
        return len(self._connection_log)

    def clear(self):
        self._connection_log.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy(counts: list) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counts:
        p = c / total
        if p > 0:
            ent -= p * math.log2(p)
    return round(ent, 4)


PORT_SERVICES = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
    25: "SMTP", 587: "SMTP/TLS", 993: "IMAP/TLS", 995: "POP3/TLS",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
    4444: "Metasploit", 1337: "C2", 6667: "IRC", 5555: "ADB",
}


def _port_service(port: int) -> str:
    return PORT_SERVICES.get(port, "")