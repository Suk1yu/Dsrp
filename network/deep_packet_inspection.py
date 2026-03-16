"""
network/deep_packet_inspection.py
Inspects packet metadata and payloads to detect suspicious DNS,
tracking domains, and possible malware C2 communication.
"""

import re
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


SUSPICIOUS_TLD_PATTERNS = [
    r"\.(xyz|top|club|online|site|fun|work|bid|stream|gq|cf|ml|tk)$",
]

C2_PATTERNS = [
    r"beacon",
    r"cmd\.php",
    r"rat\.php",
    r"upload\.php\?id=",
    r"/gate\.php",
    r"/panel/",
    r"exec=",
    r"shell\.php",
    r"c2server",
    r"\/tasks\/get",
]

DNS_TUNNEL_PATTERNS = [
    r"[a-f0-9]{20,}\.",           # long hex subdomains
    r"([a-z0-9]{30,})\.",         # very long subdomain
    r"\d+\.\d+\.\d+\.\d+\.",     # encoded IP in subdomain
]

TRACKING_DOMAINS_BUILTIN = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "facebook.com/tr", "connect.facebook.net", "ads.twitter.com",
    "advertising.apple.com", "mopub.com", "inmobi.com", "admob.com",
    "flurry.com", "mixpanel.com", "segment.com", "amplitude.com",
    "appsflyer.com", "adjust.com", "branch.io", "kochava.com",
    "taboola.com", "outbrain.com", "scorecard research.com",
    "addthis.com", "sharethis.com", "quora.com/qevents",
    "hotjar.com", "mouseflow.com", "fullstory.com", "logrocket.com",
    "datadog-browser-agent", "newrelic.com",
}


@dataclass
class DPIResult:
    packet_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    findings: list = field(default_factory=list)
    severity: str = "CLEAN"
    dns_query: str = ""
    payload_excerpt: str = ""


class DeepPacketInspector:
    """
    Performs deep inspection of packet metadata and partial payloads.
    Detects: suspicious DNS, tracking domains, C2 indicators, DNS tunneling.
    """

    def __init__(self, tracker_db_path: Optional[str] = None):
        self._tracker_domains = set(TRACKING_DOMAINS_BUILTIN)
        self._packet_counter = 0

        if tracker_db_path and Path(tracker_db_path).exists():
            self._load_tracker_db(tracker_db_path)

        # Compile patterns
        self._c2_re = [re.compile(p, re.IGNORECASE) for p in C2_PATTERNS]
        self._dns_tunnel_re = [re.compile(p, re.IGNORECASE) for p in DNS_TUNNEL_PATTERNS]
        self._suspicious_tld_re = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_TLD_PATTERNS]

    def _load_tracker_db(self, path: str):
        try:
            with open(path) as f:
                data = json.load(f)
                if isinstance(data, list):
                    self._tracker_domains.update(data)
                elif isinstance(data, dict):
                    for entry in data.values():
                        if isinstance(entry, dict):
                            self._tracker_domains.update(entry.get("domains", []))
        except Exception:
            pass

    def inspect(self, record) -> DPIResult:
        """Inspect a PacketRecord and return a DPIResult."""
        self._packet_counter += 1
        findings = []
        severity = "CLEAN"

        src_ip = getattr(record, "src_ip", "")
        dst_ip = getattr(record, "dst_ip", "")
        dst_port = getattr(record, "dst_port", 0)
        protocol = getattr(record, "protocol", "")
        dns_query = getattr(record, "dns_query", "")
        raw_summary = getattr(record, "raw_summary", "")

        result = DPIResult(
            packet_id=f"PKT-{self._packet_counter:06d}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            dns_query=dns_query,
        )

        # DNS inspection
        if dns_query:
            f, sev = self._inspect_dns(dns_query)
            findings.extend(f)
            severity = self._escalate(severity, sev)

        # Payload / summary inspection
        payload_text = raw_summary or ""
        if payload_text:
            f, sev = self._inspect_payload(payload_text)
            findings.extend(f)
            severity = self._escalate(severity, sev)
            result.payload_excerpt = payload_text[:120]

        # Port-based checks
        f, sev = self._inspect_ports(dst_port, protocol)
        findings.extend(f)
        severity = self._escalate(severity, sev)

        result.findings = findings
        result.severity = severity
        return result

    def _inspect_dns(self, query: str) -> tuple:
        findings = []
        severity = "CLEAN"
        lower = query.lower().strip(".")

        # Tracking domain check
        for tracker in self._tracker_domains:
            if tracker in lower:
                findings.append(f"TRACKER_DNS: Query to known tracking domain [{query}]")
                severity = self._escalate(severity, "MEDIUM")
                break

        # Suspicious TLD
        for pattern in self._suspicious_tld_re:
            if pattern.search(lower):
                findings.append(f"SUSPICIOUS_TLD: Unusual TLD in [{query}]")
                severity = self._escalate(severity, "MEDIUM")
                break

        # DNS tunneling detection
        for pattern in self._dns_tunnel_re:
            if pattern.search(lower):
                findings.append(f"DNS_TUNNEL: Possible DNS tunneling pattern in [{query}]")
                severity = self._escalate(severity, "HIGH")
                break

        # Very long hostname
        if len(lower) > 60:
            findings.append(f"DNS_LONG: Unusually long hostname ({len(lower)} chars) — possible tunnel")
            severity = self._escalate(severity, "MEDIUM")

        # Too many subdomains
        parts = lower.split(".")
        if len(parts) > 6:
            findings.append(f"DNS_DEPTH: Deep subdomain hierarchy ({len(parts)} levels) — tunnel indicator")
            severity = self._escalate(severity, "MEDIUM")

        return findings, severity

    def _inspect_payload(self, payload: str) -> tuple:
        findings = []
        severity = "CLEAN"

        # C2 pattern matching
        for pattern in self._c2_re:
            if pattern.search(payload):
                findings.append(f"C2_INDICATOR: Pattern [{pattern.pattern}] matched in payload")
                severity = self._escalate(severity, "HIGH")

        return findings, severity

    def _inspect_ports(self, port: int, protocol: str) -> tuple:
        findings = []
        severity = "CLEAN"

        KNOWN_C2_PORTS = {
            4444: "Metasploit default listener",
            1337: "Common hacker/C2 port",
            31337: "Classic elite/C2 port",
            6667: "IRC — possible botnet C2",
            6666: "IRC alt — possible botnet C2",
            7777: "Common RAT port",
            5555: "ADB over network — remote control risk",
            9999: "Common malware C2 port",
        }

        if port in KNOWN_C2_PORTS:
            findings.append(f"SUSPICIOUS_PORT: Port {port} — {KNOWN_C2_PORTS[port]}")
            severity = self._escalate(severity, "HIGH")

        # ADB over TCP
        if port == 5555 and protocol in ("TCP",):
            findings.append("ADB_OVER_TCP: Android Debug Bridge over TCP detected — serious risk")
            severity = self._escalate(severity, "CRITICAL")

        return findings, severity

    def _escalate(self, current: str, new: str) -> str:
        order = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        ci = order.index(current) if current in order else 0
        ni = order.index(new) if new in order else 0
        return order[max(ci, ni)]

    def add_tracker_domain(self, domain: str):
        self._tracker_domains.add(domain.lower())

    def get_tracker_count(self) -> int:
        return len(self._tracker_domains)