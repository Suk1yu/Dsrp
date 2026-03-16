"""
defense/policy_engine.py

Security policy engine — defines three operational modes and
translates threat signals into enforcement decisions.

Modes:
  MONITOR   — observe only, no blocking
  DEFENSIVE — block trackers + known malicious, alert everything else
  STRICT    — block trackers + malicious + suspicious, flag apps

Decision output is always a PolicyDecision object with:
  action: ALLOW / ALERT / BLOCK / FLAG_APP
  reason: human-readable
  evidence: structured dict

CPU cost: O(1) per decision — pure logic, no I/O.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PolicyMode(str, Enum):
    MONITOR   = "MONITOR"     # watch only
    DEFENSIVE = "DEFENSIVE"   # block trackers + malicious
    STRICT    = "STRICT"      # maximum blocking


class Action(str, Enum):
    ALLOW    = "ALLOW"
    ALERT    = "ALERT"
    BLOCK    = "BLOCK"
    FLAG_APP = "FLAG_APP"


@dataclass
class PolicyDecision:
    action: Action
    reason: str
    threat_type: str = ""           # tracker / malicious / c2 / suspicious / anomaly
    confidence: float = 1.0         # 0.0–1.0
    ioc: str = ""
    app: str = ""
    evidence: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    auto_enforced: bool = False

    @property
    def should_block(self) -> bool:
        return self.action == Action.BLOCK

    @property
    def should_alert(self) -> bool:
        return self.action in (Action.ALERT, Action.BLOCK, Action.FLAG_APP)

    def summary(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{self.action.value}] {ts} {self.reason}"


# ---------------------------------------------------------------------------
# Policy rule thresholds per mode
# ---------------------------------------------------------------------------

MODE_RULES = {
    PolicyMode.MONITOR: {
        "block_trackers":   False,
        "block_malicious":  False,
        "block_c2":         False,
        "block_suspicious": False,
        "alert_trackers":   True,
        "alert_malicious":  True,
        "alert_anomaly":    True,
        "flag_apps":        False,
    },
    PolicyMode.DEFENSIVE: {
        "block_trackers":   True,
        "block_malicious":  True,
        "block_c2":         True,
        "block_suspicious": False,
        "alert_trackers":   True,
        "alert_malicious":  True,
        "alert_anomaly":    True,
        "flag_apps":        True,
    },
    PolicyMode.STRICT: {
        "block_trackers":   True,
        "block_malicious":  True,
        "block_c2":         True,
        "block_suspicious": True,
        "alert_trackers":   True,
        "alert_malicious":  True,
        "alert_anomaly":    True,
        "flag_apps":        True,
    },
}


class PolicyEngine:
    """
    Converts threat signals into enforcement decisions based on active mode.
    Thread-safe, stateless per-call (state lives in the blocklist, not here).
    """

    def __init__(self, mode: PolicyMode = PolicyMode.DEFENSIVE):
        self.mode = mode
        self._rules = MODE_RULES[mode]
        # Whitelist: domains / IPs that should never be blocked
        self._whitelist: set = {
            "google.com", "googleapis.com", "gstatic.com",
            "apple.com", "microsoft.com", "cloudflare.com",
            "akamai.com", "fastly.com", "localhost", "127.0.0.1",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_mode(self, mode: PolicyMode):
        self.mode = mode
        self._rules = MODE_RULES[mode]

    def add_whitelist(self, entry: str):
        self._whitelist.add(entry.lower().strip("."))

    def remove_whitelist(self, entry: str):
        self._whitelist.discard(entry.lower().strip("."))

    def evaluate_domain(self, domain: str,
                         threat_type: str = "",
                         confidence: float = 1.0,
                         tracker_name: str = "",
                         app: str = "") -> PolicyDecision:
        """
        Evaluate what action to take for a domain contact.
        threat_type: tracker / malicious / c2 / suspicious / clean
        """
        domain = domain.lower().strip(".")

        # Whitelist check — always ALLOW
        if self._is_whitelisted(domain):
            return PolicyDecision(
                action=Action.ALLOW,
                reason=f"{domain} is whitelisted",
                ioc=domain, app=app,
            )

        rules = self._rules

        if threat_type == "tracker":
            if rules["block_trackers"]:
                return PolicyDecision(
                    action=Action.BLOCK,
                    reason=f"Tracker domain blocked: {tracker_name or domain}",
                    threat_type="tracker",
                    confidence=confidence,
                    ioc=domain, app=app,
                    evidence={"tracker_name": tracker_name},
                )
            elif rules["alert_trackers"]:
                return PolicyDecision(
                    action=Action.ALERT,
                    reason=f"Tracker detected: {tracker_name or domain}",
                    threat_type="tracker",
                    confidence=confidence,
                    ioc=domain, app=app,
                )

        elif threat_type in ("malicious", "c2"):
            if rules["block_malicious"] or rules["block_c2"]:
                return PolicyDecision(
                    action=Action.BLOCK,
                    reason=f"Malicious domain blocked: {domain}",
                    threat_type=threat_type,
                    confidence=confidence,
                    ioc=domain, app=app,
                )
            elif rules["alert_malicious"]:
                return PolicyDecision(
                    action=Action.ALERT,
                    reason=f"Malicious domain detected: {domain}",
                    threat_type=threat_type,
                    confidence=confidence,
                    ioc=domain, app=app,
                )

        elif threat_type == "suspicious":
            if rules["block_suspicious"]:
                return PolicyDecision(
                    action=Action.BLOCK,
                    reason=f"Suspicious domain blocked: {domain}",
                    threat_type="suspicious",
                    confidence=confidence,
                    ioc=domain, app=app,
                )
            elif rules["alert_malicious"]:
                return PolicyDecision(
                    action=Action.ALERT,
                    reason=f"Suspicious domain: {domain}",
                    threat_type="suspicious",
                    confidence=confidence,
                    ioc=domain, app=app,
                )

        return PolicyDecision(
            action=Action.ALLOW,
            reason=f"{domain} allowed",
            ioc=domain, app=app,
        )

    def evaluate_ip(self, ip: str,
                     threat_type: str = "",
                     confidence: float = 1.0,
                     app: str = "") -> PolicyDecision:
        """Evaluate an IP address."""
        if threat_type in ("malicious", "c2") and \
                self._rules.get("block_malicious"):
            return PolicyDecision(
                action=Action.BLOCK,
                reason=f"Malicious IP blocked: {ip}",
                threat_type=threat_type,
                confidence=confidence,
                ioc=ip, app=app,
            )
        if threat_type in ("malicious", "c2") and \
                self._rules.get("alert_malicious"):
            return PolicyDecision(
                action=Action.ALERT,
                reason=f"Malicious IP detected: {ip}",
                threat_type=threat_type,
                confidence=confidence,
                ioc=ip, app=app,
            )
        return PolicyDecision(action=Action.ALLOW, reason=f"{ip} allowed",
                              ioc=ip, app=app)

    def evaluate_app(self, app: str, risk_level: str,
                      ml_probability: float = 0.0) -> PolicyDecision:
        """Evaluate an app based on its risk profile."""
        if risk_level in ("CRITICAL", "HIGH") and self._rules["flag_apps"]:
            return PolicyDecision(
                action=Action.FLAG_APP,
                reason=f"High-risk app flagged: {app} (risk={risk_level}, p={ml_probability:.0%})",
                threat_type="malicious_app",
                confidence=ml_probability,
                app=app,
                evidence={"risk_level": risk_level, "probability": ml_probability},
            )
        if risk_level == "MEDIUM" and self._rules["alert_malicious"]:
            return PolicyDecision(
                action=Action.ALERT,
                reason=f"Suspicious app: {app} (risk={risk_level})",
                threat_type="suspicious_app",
                confidence=ml_probability,
                app=app,
            )
        return PolicyDecision(action=Action.ALLOW,
                              reason=f"{app} within policy", app=app)

    def evaluate_anomaly(self, description: str,
                          severity: str = "MEDIUM") -> PolicyDecision:
        """Evaluate a traffic anomaly signal."""
        if not self._rules.get("alert_anomaly"):
            return PolicyDecision(action=Action.ALLOW, reason="anomaly monitoring off")
        return PolicyDecision(
            action=Action.ALERT,
            reason=f"Traffic anomaly [{severity}]: {description}",
            threat_type="anomaly",
            confidence={"CRITICAL": 0.95, "HIGH": 0.8,
                        "MEDIUM": 0.6, "LOW": 0.4}.get(severity, 0.5),
        )

    def get_mode_summary(self) -> dict:
        return {
            "mode": self.mode.value,
            "rules": dict(self._rules),
            "whitelist_count": len(self._whitelist),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_whitelisted(self, domain: str) -> bool:
        if domain in self._whitelist:
            return True
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._whitelist:
                return True
        return False