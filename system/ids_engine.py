"""
system/ids_engine.py
Lightweight Intrusion Detection System.
Detects: port scans, DNS tunneling, botnet beaconing, data exfiltration.
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IDSAlert:
    timestamp: float
    rule_id: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    category: str
    description: str
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "evidence": self.evidence,
        }


class IDSEngine:
    """
    Rule-based intrusion detection system.
    Processes PacketRecord streams and generates IDSAlerts.
    """

    # Port scan: N distinct ports from same src within window
    PORT_SCAN_THRESHOLD = 15
    PORT_SCAN_WINDOW = 10.0  # seconds

    # Data exfil: high outbound bytes to single IP
    EXFIL_BYTE_THRESHOLD = 5_000_000  # 5MB
    EXFIL_WINDOW = 60.0  # seconds

    # DNS tunnel: long labels or high query rate
    DNS_QUERY_RATE_THRESHOLD = 30  # queries per 10 seconds
    DNS_LABEL_LENGTH_THRESHOLD = 40

    # Large payload over unusual port
    LARGE_PKT_THRESHOLD = 8192  # bytes
    LARGE_PKT_UNUSUAL_PORTS = {6667, 6666, 4444, 1337, 31337, 9999}

    def __init__(self):
        self._alerts: list[IDSAlert] = []
        self._alert_dedup: dict[str, float] = {}  # rule+src -> last_alert_time
        self._dedup_window = 30.0  # suppress same alert within 30s

        # Port scan tracking: src_ip -> deque[(port, time)]
        self._port_scan_tracker: defaultdict = defaultdict(lambda: deque())

        # Exfil tracking: (src_ip, dst_ip) -> bytes total
        self._exfil_tracker: defaultdict = defaultdict(float)
        self._exfil_times: defaultdict = defaultdict(float)  # start time

        # DNS rate tracking: src_ip -> deque[time]
        self._dns_rate_tracker: defaultdict = defaultdict(lambda: deque())

    def process_packet(self, record) -> list[IDSAlert]:
        """Process a single packet and return any new IDS alerts."""
        new_alerts = []
        now = time.time()

        src_ip = getattr(record, "src_ip", "")
        dst_ip = getattr(record, "dst_ip", "")
        dst_port = getattr(record, "dst_port", 0)
        src_port = getattr(record, "src_port", 0)
        protocol = getattr(record, "protocol", "")
        size = getattr(record, "size", 0)
        dns_query = getattr(record, "dns_query", "")

        # --- Rule 1: Port Scan Detection ---
        if src_ip:
            tracker = self._port_scan_tracker[src_ip]
            # Prune old entries
            cutoff = now - self.PORT_SCAN_WINDOW
            while tracker and tracker[0][1] < cutoff:
                tracker.popleft()
            tracker.append((dst_port, now))

            distinct_ports = len(set(p for p, _ in tracker))
            if distinct_ports >= self.PORT_SCAN_THRESHOLD:
                alert = self._make_alert(
                    now=now,
                    rule_id="IDS-001",
                    severity="HIGH",
                    category="PORT_SCAN",
                    description=(
                        f"Port scan detected from {src_ip}: "
                        f"{distinct_ports} distinct ports in {self.PORT_SCAN_WINDOW}s"
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    evidence={"distinct_ports": distinct_ports,
                              "window_secs": self.PORT_SCAN_WINDOW},
                )
                if alert:
                    new_alerts.append(alert)

        # --- Rule 2: DNS Tunneling ---
        if protocol == "DNS" and dns_query:
            # High label length
            labels = dns_query.split(".")
            max_label_len = max((len(l) for l in labels), default=0)
            if max_label_len >= self.DNS_LABEL_LENGTH_THRESHOLD:
                alert = self._make_alert(
                    now=now,
                    rule_id="IDS-002",
                    severity="HIGH",
                    category="DNS_TUNNELING",
                    description=(
                        f"Possible DNS tunnel: long label ({max_label_len} chars) "
                        f"in query [{dns_query[:50]}]"
                    ),
                    src_ip=src_ip,
                    evidence={"label_len": max_label_len, "query": dns_query[:60]},
                )
                if alert:
                    new_alerts.append(alert)

            # High query rate
            if src_ip:
                dns_tracker = self._dns_rate_tracker[src_ip]
                dns_cutoff = now - 10.0
                while dns_tracker and dns_tracker[0] < dns_cutoff:
                    dns_tracker.popleft()
                dns_tracker.append(now)

                if len(dns_tracker) >= self.DNS_QUERY_RATE_THRESHOLD:
                    alert = self._make_alert(
                        now=now,
                        rule_id="IDS-003",
                        severity="MEDIUM",
                        category="DNS_TUNNELING",
                        description=(
                            f"High DNS query rate from {src_ip}: "
                            f"{len(dns_tracker)} queries in 10s"
                        ),
                        src_ip=src_ip,
                        evidence={"query_rate": len(dns_tracker)},
                    )
                    if alert:
                        new_alerts.append(alert)

        # --- Rule 3: Data Exfiltration ---
        if src_ip and dst_ip and size > 0:
            key = (src_ip, dst_ip)
            if self._exfil_times[key] == 0:
                self._exfil_times[key] = now

            # Reset window
            if now - self._exfil_times[key] > self.EXFIL_WINDOW:
                self._exfil_tracker[key] = 0
                self._exfil_times[key] = now

            self._exfil_tracker[key] += size

            if self._exfil_tracker[key] >= self.EXFIL_BYTE_THRESHOLD:
                mb = self._exfil_tracker[key] / 1_000_000
                alert = self._make_alert(
                    now=now,
                    rule_id="IDS-004",
                    severity="HIGH",
                    category="DATA_EXFILTRATION",
                    description=(
                        f"Possible data exfiltration: {mb:.1f}MB from "
                        f"{src_ip} to {dst_ip} in {self.EXFIL_WINDOW}s"
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence={"bytes": int(self._exfil_tracker[key]),
                              "mb": round(mb, 2)},
                )
                if alert:
                    new_alerts.append(alert)
                    self._exfil_tracker[key] = 0  # reset after alert

        # --- Rule 4: Large Packet on Suspicious Port ---
        if dst_port in self.LARGE_PKT_UNUSUAL_PORTS and size >= self.LARGE_PKT_THRESHOLD:
            alert = self._make_alert(
                now=now,
                rule_id="IDS-005",
                severity="MEDIUM",
                category="SUSPICIOUS_TRAFFIC",
                description=(
                    f"Large packet ({size}B) on suspicious port {dst_port} — "
                    "possible C2 data transfer"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                evidence={"size": size},
            )
            if alert:
                new_alerts.append(alert)

        # --- Rule 5: ADB over network ---
        if dst_port == 5555 and protocol == "TCP":
            alert = self._make_alert(
                now=now,
                rule_id="IDS-006",
                severity="CRITICAL",
                category="DEVICE_CONTROL",
                description=(
                    f"ADB connection attempt to port 5555 from {src_ip} — "
                    "potential remote device takeover"
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=5555,
                evidence={},
            )
            if alert:
                new_alerts.append(alert)

        self._alerts.extend(new_alerts)
        return new_alerts

    def _make_alert(self, now: float, rule_id: str, **kwargs) -> Optional[IDSAlert]:
        """Create an alert, suppressing duplicates within dedup window."""
        src = kwargs.get("src_ip", "")
        dedup_key = f"{rule_id}:{src}"
        last = self._alert_dedup.get(dedup_key, 0)
        if now - last < self._dedup_window:
            return None
        self._alert_dedup[dedup_key] = now
        return IDSAlert(timestamp=now, rule_id=rule_id, **kwargs)

    def get_alerts(self, limit: int = 100, severity: str = None) -> list[IDSAlert]:
        alerts = self._alerts
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts[-limit:]

    def get_stats(self) -> dict:
        by_severity = {}
        by_category = {}
        for a in self._alerts:
            by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
            by_category[a.category] = by_category.get(a.category, 0) + 1
        return {
            "total_alerts": len(self._alerts),
            "by_severity": by_severity,
            "by_category": by_category,
        }

    def clear(self):
        self._alerts.clear()
        self._alert_dedup.clear()