"""
ids/ids_engine.py

Lightweight IDS engine — event-driven rule evaluation.
Inspired by Snort/Suricata but built for mobile ARM.

Architecture:
  - Packet/connection events are fed via process_event()
  - Only runs rules relevant to the current event type
  - Alert deduplication with configurable suppression window
  - Severity escalation via counters

CPU cost: ~1–2% (rule matching is O(1)–O(k) per event, not per byte)
"""

import time
import json
import threading
from collections import deque, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable

from ids.signature_rules import (
    IDSRule, IDSMatch, build_default_ruleset,
    PortScanRule, DNSTunnelingRule, BotnetBeaconingRule,
    DataExfiltrationRule, ADBOverTCPRule, SuspiciousPortRule,
    SNISuspiciousRule,
)


# ---------------------------------------------------------------------------
# Alert with dedup tracking
# ---------------------------------------------------------------------------

@dataclass
class IDSAlert:
    alert_id: int
    timestamp: float
    rule_id: str
    rule_name: str
    severity: str
    category: str
    description: str
    evidence: dict = field(default_factory=dict)
    mitre: str = ""
    acknowledged: bool = False
    count: int = 1             # how many times this rule fired

    def age_secs(self) -> float:
        return time.time() - self.timestamp

    def to_dict(self) -> dict:
        return {
            "id": self.alert_id,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "mitre": self.mitre,
            "count": self.count,
        }

    def badge(self) -> str:
        colors = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🔵",
            "INFO":     "⚪",
        }
        return colors.get(self.severity, "⚪")

    def one_line(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        count_str = f" ×{self.count}" if self.count > 1 else ""
        return f"{self.badge()} [{self.severity}] {ts} {self.description}{count_str}"


SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


# ---------------------------------------------------------------------------
# IDS Engine
# ---------------------------------------------------------------------------

class IDSEngine:
    """
    Processes network events through the IDS ruleset.
    Manages alert lifecycle: generation → dedup → escalation → output.

    Usage:
        engine = IDSEngine()
        engine.process_event({"src_ip": "...", "dst_port": 4444, ...})
        alerts = engine.get_alerts()
    """

    DEDUP_WINDOW     = 30.0    # suppress identical rule match within 30s
    MAX_ALERTS       = 1000    # circular buffer
    ESCALATE_AFTER   = 5       # escalate severity after N repeated matches
    LOG_PATH         = Path(__file__).parent.parent / "data" / "ids_alerts.jsonl"

    def __init__(self,
                 rules: list[IDSRule] = None,
                 callbacks: list[Callable] = None,
                 log_to_file: bool = False):
        self._rules = rules or build_default_ruleset()
        self._callbacks: list[Callable] = callbacks or []
        self._log_to_file = log_to_file

        self._alerts: deque = deque(maxlen=self.MAX_ALERTS)
        self._alert_counter = 0
        self._lock = threading.Lock()

        # Dedup: rule_id -> (last_time, count)
        self._dedup: dict = {}

        # Stats
        self._stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "by_severity": defaultdict(int),
            "by_category": defaultdict(int),
            "by_rule": defaultdict(int),
        }

        # Rule type index for fast dispatch
        self._rule_index = self._build_index()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_callback(self, fn: Callable):
        """Register callback fn(IDSAlert) on every new alert."""
        self._callbacks.append(fn)

    def add_rule(self, rule: IDSRule):
        self._rules.append(rule)
        self._rule_index = self._build_index()

    def process_event(self, context: dict) -> list[IDSAlert]:
        """
        Feed a network event into the IDS.
        context keys (all optional):
          src_ip, dst_ip, src_port, dst_port, protocol,
          size, dns_query, sni, timestamp
        Returns list of new IDSAlerts generated.
        """
        with self._lock:
            self._stats["events_processed"] += 1

        # Determine which rules apply
        applicable = self._get_applicable_rules(context)
        new_alerts = []

        for rule in applicable:
            if not rule.enabled:
                continue
            try:
                match = rule.match(context)
            except Exception:
                continue

            if match is None:
                continue

            alert = self._handle_match(match)
            if alert:
                new_alerts.append(alert)

        return new_alerts

    def process_packet(self, packet) -> list[IDSAlert]:
        """Convenience: feed a PacketRecord object."""
        ctx = {
            "src_ip":   getattr(packet, "src_ip", ""),
            "dst_ip":   getattr(packet, "dst_ip", ""),
            "src_port": getattr(packet, "src_port", 0),
            "dst_port": getattr(packet, "dst_port", 0),
            "protocol": getattr(packet, "protocol", ""),
            "size":     getattr(packet, "size", 0),
            "dns_query":getattr(packet, "dns_query", ""),
            "timestamp":getattr(packet, "timestamp", time.time()),
        }
        return self.process_event(ctx)

    def process_connection(self, conn) -> list[IDSAlert]:
        """Convenience: feed a ConnectionMeta object."""
        ctx = {
            "src_ip":   getattr(conn, "local_ip", ""),
            "dst_ip":   getattr(conn, "remote_ip", ""),
            "src_port": getattr(conn, "local_port", 0),
            "dst_port": getattr(conn, "remote_port", 0),
            "protocol": getattr(conn, "protocol", "TCP"),
            "size":     0,
        }
        return self.process_event(ctx)

    def get_alerts(self,
                   limit: int = 100,
                   min_severity: str = "LOW",
                   category: str = None,
                   unacked_only: bool = False) -> list[IDSAlert]:
        min_score = SEVERITY_ORDER.get(min_severity, 0)
        with self._lock:
            alerts = list(self._alerts)

        alerts = [a for a in alerts
                  if SEVERITY_ORDER.get(a.severity, 0) >= min_score]
        if category:
            alerts = [a for a in alerts if a.category == category]
        if unacked_only:
            alerts = [a for a in alerts if not a.acknowledged]

        return alerts[-limit:]

    def get_latest_alerts(self, n: int = 10) -> list[IDSAlert]:
        with self._lock:
            return list(self._alerts)[-n:]

    def get_critical_alerts(self) -> list[IDSAlert]:
        return self.get_alerts(min_severity="HIGH")

    def acknowledge(self, alert_id: int):
        with self._lock:
            for a in self._alerts:
                if a.alert_id == alert_id:
                    a.acknowledged = True
                    break

    def acknowledge_all(self):
        with self._lock:
            for a in self._alerts:
                a.acknowledged = True

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "events_processed": self._stats["events_processed"],
                "alerts_generated": self._stats["alerts_generated"],
                "active_alerts": sum(1 for a in self._alerts if not a.acknowledged),
                "by_severity": dict(self._stats["by_severity"]),
                "by_category": dict(self._stats["by_category"]),
                "rules_loaded": len(self._rules),
            }

    def get_rule_list(self) -> list[dict]:
        return [
            {"id": r.rule_id, "name": r.name,
             "severity": r.severity, "category": r.category,
             "enabled": r.enabled}
            for r in self._rules
        ]

    def set_rule_enabled(self, rule_id: str, enabled: bool):
        for rule in self._rules:
            if rule.rule_id == rule_id:
                rule.enabled = enabled
                break

    def export_alerts_json(self, path: str):
        with self._lock:
            alerts = list(self._alerts)
        with open(path, "w") as f:
            json.dump([a.to_dict() for a in alerts], f, indent=2)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _handle_match(self, match: IDSMatch) -> Optional[IDSAlert]:
        now = time.time()
        dedup_key = f"{match.rule_id}:{match.description[:40]}"

        with self._lock:
            last_time, count = self._dedup.get(dedup_key, (0, 0))

            # Within dedup window — update count but don't emit new alert
            if now - last_time < self.DEDUP_WINDOW:
                self._dedup[dedup_key] = (last_time, count + 1)
                # Update existing alert count
                for a in reversed(self._alerts):
                    if a.rule_id == match.rule_id:
                        a.count = count + 1
                        # Escalate severity on repeated matches
                        if count + 1 >= self.ESCALATE_AFTER:
                            a.severity = self._escalate(a.severity)
                        break
                return None

            # New alert
            self._dedup[dedup_key] = (now, 1)
            self._alert_counter += 1
            severity = match.severity

            alert = IDSAlert(
                alert_id=self._alert_counter,
                timestamp=now,
                rule_id=match.rule_id,
                rule_name=match.rule_name,
                severity=severity,
                category=match.category,
                description=match.description,
                evidence=match.evidence,
                mitre=match.mitre_technique,
            )

            self._alerts.append(alert)
            self._stats["alerts_generated"] += 1
            self._stats["by_severity"][severity] += 1
            self._stats["by_category"][match.category] += 1
            self._stats["by_rule"][match.rule_id] += 1

        # Log to file
        if self._log_to_file:
            self._log_alert(alert)

        # Callbacks
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

        return alert

    def _escalate(self, severity: str) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        idx = order.index(severity) if severity in order else 0
        return order[min(idx + 1, len(order) - 1)]

    def _log_alert(self, alert: IDSAlert):
        try:
            self.LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(self.LOG_PATH, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except Exception:
            pass

    def _get_applicable_rules(self, context: dict) -> list[IDSRule]:
        """Fast dispatch: return only rules relevant to this event type."""
        applicable = []
        has_dns    = bool(context.get("dns_query"))
        has_port   = bool(context.get("dst_port"))
        has_size   = bool(context.get("size"))
        has_sni    = bool(context.get("sni"))

        for rule in self._rules:
            if isinstance(rule, DNSTunnelingRule) and not has_dns:
                continue
            if isinstance(rule, (DataExfiltrationRule,)) and not has_size:
                continue
            if isinstance(rule, SNISuspiciousRule) and not (has_dns or has_sni):
                continue
            applicable.append(rule)

        return applicable

    def _build_index(self) -> dict:
        idx = {
            "all": self._rules,
            "dns": [r for r in self._rules if isinstance(r, DNSTunnelingRule)],
            "port": [r for r in self._rules if isinstance(r, (SuspiciousPortRule, ADBOverTCPRule, PortScanRule))],
            "flow": [r for r in self._rules if isinstance(r, (BotnetBeaconingRule, DataExfiltrationRule))],
        }
        return idx