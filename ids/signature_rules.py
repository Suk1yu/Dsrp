"""
ids/signature_rules.py

IDS signature rule definitions.
Inspired by Snort/Suricata but lightweight for mobile.

Each rule is a dataclass with:
  - id / name / category
  - threshold values
  - check() method → None | IDSMatch

Rules are event-driven: evaluated only when relevant traffic is seen.
CPU cost: O(1) per packet per matching rule type.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Callable


# ---------------------------------------------------------------------------
# Match result
# ---------------------------------------------------------------------------

@dataclass
class IDSMatch:
    rule_id: str
    rule_name: str
    severity: str          # INFO / LOW / MEDIUM / HIGH / CRITICAL
    category: str
    description: str
    evidence: dict = field(default_factory=dict)
    mitre_technique: str = ""


# ---------------------------------------------------------------------------
# Base rule class
# ---------------------------------------------------------------------------

@dataclass
class IDSRule:
    rule_id: str
    name: str
    severity: str
    category: str
    description_template: str
    enabled: bool = True
    mitre: str = ""

    def match(self, context: dict) -> Optional[IDSMatch]:
        """Override in subclasses. context: arbitrary dict of event data."""
        raise NotImplementedError

    def _make_match(self, description: str,
                    evidence: dict = None) -> IDSMatch:
        return IDSMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            category=self.category,
            description=description,
            evidence=evidence or {},
            mitre_technique=self.mitre,
        )


# ---------------------------------------------------------------------------
# Rule: Port Scan
# ---------------------------------------------------------------------------

@dataclass
class PortScanRule(IDSRule):
    """Detects N unique ports from same source within T seconds."""
    port_threshold: int = 10
    window_secs: float = 5.0

    def __post_init__(self):
        self._tracker: dict = {}   # src_ip -> [(port, time)]

    def match(self, context: dict) -> Optional[IDSMatch]:
        import time
        src_ip = context.get("src_ip", "")
        dst_port = context.get("dst_port", 0)
        if not src_ip or not dst_port:
            return None

        now = time.time()
        if src_ip not in self._tracker:
            self._tracker[src_ip] = []

        entries = self._tracker[src_ip]
        cutoff = now - self.window_secs
        entries[:] = [(p, t) for p, t in entries if t > cutoff]
        entries.append((dst_port, now))

        distinct = len(set(p for p, _ in entries))
        if distinct >= self.port_threshold:
            return self._make_match(
                f"Port scan from {src_ip}: {distinct} ports in {self.window_secs:.0f}s",
                {"src_ip": src_ip, "distinct_ports": distinct,
                 "window_secs": self.window_secs}
            )
        return None


# ---------------------------------------------------------------------------
# Rule: DNS Tunneling
# ---------------------------------------------------------------------------

@dataclass
class DNSTunnelingRule(IDSRule):
    """Detects DNS tunneling via long labels and high query rates."""
    label_len_threshold: int = 40
    query_rate_threshold: int = 80   # per minute
    _query_times: list = field(default_factory=list)

    def match(self, context: dict) -> Optional[IDSMatch]:
        import time
        dns_query = context.get("dns_query", "")
        if not dns_query:
            return None

        now = time.time()

        # Long label check
        labels = dns_query.split(".")
        max_label = max((len(l) for l in labels), default=0)
        if max_label >= self.label_len_threshold:
            return self._make_match(
                f"DNS tunnel suspect: label length {max_label} in [{dns_query[:50]}]",
                {"query": dns_query[:60], "max_label_len": max_label}
            )

        # High rate check
        src_ip = context.get("src_ip", "")
        self._query_times.append(now)
        cutoff = now - 60.0
        self._query_times = [t for t in self._query_times if t > cutoff]

        rate = len(self._query_times)
        if rate >= self.query_rate_threshold:
            return self._make_match(
                f"High DNS query rate: {rate} queries/min from {src_ip}",
                {"queries_per_min": rate, "src_ip": src_ip}
            )

        # Deep subdomain hierarchy
        if len(labels) > 7:
            return self._make_match(
                f"Deep DNS subdomain ({len(labels)} levels): [{dns_query[:50]}]",
                {"depth": len(labels), "query": dns_query[:60]}
            )

        return None


# ---------------------------------------------------------------------------
# Rule: Botnet Beaconing
# ---------------------------------------------------------------------------

@dataclass
class BotnetBeaconingRule(IDSRule):
    """Detects regular-interval connections to same IP."""
    min_packets: int = 6
    window_secs: float = 180.0
    max_jitter: float = 0.15      # std/mean ratio
    _dst_times: dict = field(default_factory=dict)

    def match(self, context: dict) -> Optional[IDSMatch]:
        import time, math
        dst_ip = context.get("dst_ip", "")
        if not dst_ip:
            return None

        now = time.time()
        if dst_ip not in self._dst_times:
            self._dst_times[dst_ip] = []

        times = self._dst_times[dst_ip]
        cutoff = now - self.window_secs
        times[:] = [t for t in times if t > cutoff]
        times.append(now)

        if len(times) < self.min_packets:
            return None

        # Compute interval regularity
        sorted_t = sorted(times)
        intervals = [b - a for a, b in zip(sorted_t, sorted_t[1:])]
        if len(intervals) < 3:
            return None

        mean_i = sum(intervals) / len(intervals)
        if mean_i < 1.0:  # too fast — not beaconing
            return None

        variance = sum((x - mean_i) ** 2 for x in intervals) / len(intervals)
        std_i = math.sqrt(variance)
        jitter = std_i / mean_i if mean_i > 0 else 1.0

        if jitter <= self.max_jitter:
            return self._make_match(
                f"Beaconing to {dst_ip}: interval {mean_i:.1f}s ±{std_i:.2f}s "
                f"(jitter={jitter:.2f}) — possible C2",
                {"dst_ip": dst_ip, "interval_mean": round(mean_i, 2),
                 "interval_std": round(std_i, 2), "jitter": round(jitter, 3),
                 "packet_count": len(times)}
            )

        return None


# ---------------------------------------------------------------------------
# Rule: Data Exfiltration
# ---------------------------------------------------------------------------

@dataclass
class DataExfiltrationRule(IDSRule):
    """Detects large outbound data transfers to single destination."""
    byte_threshold: int = 10_000_000   # 10 MB
    window_secs: float = 60.0
    _bytes_map: dict = field(default_factory=dict)
    _time_map: dict = field(default_factory=dict)

    def match(self, context: dict) -> Optional[IDSMatch]:
        import time
        src_ip = context.get("src_ip", "")
        dst_ip = context.get("dst_ip", "")
        size   = context.get("size", 0)
        if not src_ip or not dst_ip or not size:
            return None

        now = time.time()
        key = (src_ip, dst_ip)

        if key not in self._time_map or now - self._time_map[key] > self.window_secs:
            self._bytes_map[key] = 0
            self._time_map[key] = now

        self._bytes_map[key] += size
        total = self._bytes_map[key]

        if total >= self.byte_threshold:
            mb = total / 1_000_000
            self._bytes_map[key] = 0   # reset after alert
            return self._make_match(
                f"Possible exfiltration: {mb:.1f}MB from {src_ip} → {dst_ip} in {self.window_secs:.0f}s",
                {"src_ip": src_ip, "dst_ip": dst_ip,
                 "bytes": total, "mb": round(mb, 2)}
            )

        return None


# ---------------------------------------------------------------------------
# Rule: ADB over TCP
# ---------------------------------------------------------------------------

@dataclass
class ADBOverTCPRule(IDSRule):
    """Detects Android Debug Bridge remote access (port 5555)."""

    def match(self, context: dict) -> Optional[IDSMatch]:
        dst_port = context.get("dst_port", 0)
        src_ip   = context.get("src_ip", "")
        protocol = context.get("protocol", "")
        if dst_port == 5555 and protocol in ("TCP", ""):
            return self._make_match(
                f"ADB over TCP from {src_ip}:5555 — remote device control risk",
                {"src_ip": src_ip, "port": 5555}
            )
        return None


# ---------------------------------------------------------------------------
# Rule: Suspicious Port
# ---------------------------------------------------------------------------

KNOWN_C2_PORTS = {
    4444: ("Metasploit default reverse shell", "CRITICAL"),
    1337: ("Common C2/hacker port", "HIGH"),
    31337: ("BackOrifice / elite C2", "HIGH"),
    6667: ("IRC botnet C2", "HIGH"),
    6666: ("IRC alt botnet C2", "MEDIUM"),
    9999: ("Common RAT port", "MEDIUM"),
    7777: ("Common RAT port", "MEDIUM"),
    12345: ("NetBus RAT (classic)", "MEDIUM"),
    54321: ("Reverse shell (classic)", "MEDIUM"),
    2222: ("Alt SSH / persistence", "LOW"),
}


@dataclass
class SuspiciousPortRule(IDSRule):
    """Matches traffic to known C2/RAT/botnet ports."""

    def match(self, context: dict) -> Optional[IDSMatch]:
        dst_port = context.get("dst_port", 0)
        if dst_port in KNOWN_C2_PORTS:
            desc, severity = KNOWN_C2_PORTS[dst_port]
            return IDSMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=severity,
                category=self.category,
                description=f"Traffic to port {dst_port}: {desc}",
                evidence={"port": dst_port, "description": desc},
                mitre_technique=self.mitre,
            )
        return None


# ---------------------------------------------------------------------------
# Rule: TLS SNI suspicious domain
# ---------------------------------------------------------------------------

SUSPICIOUS_SNI_PATTERNS = [
    r"\.onion\.",                  # Tor
    r"bit\.ly|tinyurl\.com",      # URL shorteners (C2 redirection)
    r"\d{4,}\.[a-z]{2,4}$",       # Numeric-heavy domain
    r"[a-z0-9]{20,}\.[a-z]{2,4}", # Very long random subdomain
    r"pastebin\.com",             # Common exfil/C2 staging
    r"ngrok\.io|serveo\.net",     # Reverse tunnel services
    r"\.ru$|\.cn$",               # High-risk TLDs (context-dependent)
]


@dataclass
class SNISuspiciousRule(IDSRule):
    """Flags suspicious TLS SNI or HTTP Host headers."""
    _compiled: list = field(default_factory=list)

    def __post_init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_SNI_PATTERNS]

    def match(self, context: dict) -> Optional[IDSMatch]:
        sni = context.get("sni", "") or context.get("dns_query", "")
        if not sni:
            return None
        for pattern in self._compiled:
            if pattern.search(sni):
                return self._make_match(
                    f"Suspicious SNI/domain [{sni[:50]}] matches pattern {pattern.pattern}",
                    {"sni": sni[:80], "pattern": pattern.pattern}
                )
        return None


# ---------------------------------------------------------------------------
# Rule registry — all active rules
# ---------------------------------------------------------------------------

def build_default_ruleset() -> list[IDSRule]:
    return [
        PortScanRule(
            rule_id="IDS-001", name="Port Scan Detection",
            severity="HIGH", category="RECON",
            description_template="Port scan from {src_ip}",
            mitre="T1046 - Network Service Scanning",
            port_threshold=10, window_secs=5.0,
        ),
        DNSTunnelingRule(
            rule_id="IDS-002", name="DNS Tunneling",
            severity="HIGH", category="EXFILTRATION",
            description_template="DNS tunneling detected",
            mitre="T1071.004 - Application Layer Protocol: DNS",
            label_len_threshold=40, query_rate_threshold=80,
        ),
        BotnetBeaconingRule(
            rule_id="IDS-003", name="Botnet Beaconing",
            severity="HIGH", category="C2",
            description_template="Regular beaconing to {dst_ip}",
            mitre="T1071 - Application Layer Protocol",
            min_packets=6, max_jitter=0.15,
        ),
        DataExfiltrationRule(
            rule_id="IDS-004", name="Data Exfiltration",
            severity="HIGH", category="EXFILTRATION",
            description_template="Large data transfer to {dst_ip}",
            mitre="T1048 - Exfiltration Over Alternative Protocol",
            byte_threshold=10_000_000,
        ),
        ADBOverTCPRule(
            rule_id="IDS-005", name="ADB Over TCP",
            severity="CRITICAL", category="DEVICE_CONTROL",
            description_template="ADB TCP access from {src_ip}",
            mitre="T1219 - Remote Access Software",
        ),
        SuspiciousPortRule(
            rule_id="IDS-006", name="Suspicious Port",
            severity="MEDIUM", category="C2",
            description_template="C2/RAT port traffic",
            mitre="T1571 - Non-Standard Port",
        ),
        SNISuspiciousRule(
            rule_id="IDS-007", name="Suspicious SNI/Domain",
            severity="MEDIUM", category="C2",
            description_template="Suspicious TLS SNI",
            mitre="T1568 - Dynamic Resolution",
        ),
    ]