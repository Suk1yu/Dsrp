"""
defense/response_engine.py

Autonomous Threat Response Engine.
Listens to all alert streams (IDS, anomaly, reputation, behavior)
and executes policy-driven responses automatically.

Response pipeline:
  Alert received
    → PolicyEngine.evaluate()
      → if BLOCK: AutoBlocker.block()
      → if FLAG: mark app in flagged set
      → if ALERT: log incident
    → IncidentLogger.log()
    → callbacks notified

Design: event-driven, not polling.
CPU cost: ~1–2% (only active when alerts fire)
"""

import time
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from defense.policy_engine import PolicyEngine, PolicyDecision, Action, PolicyMode
from defense.auto_blocker import AutoBlocker


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    incident_id: int
    timestamp: float
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW
    source: str             # IDS / ANOMALY / REPUTATION / BEHAVIOR
    description: str
    ioc: str = ""
    app: str = ""
    actions_taken: list = field(default_factory=list)
    decision: Optional[PolicyDecision] = None
    acknowledged: bool = False

    def age_mins(self) -> float:
        return (time.time() - self.timestamp) / 60.0

    def to_dict(self) -> dict:
        return {
            "id": self.incident_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "ioc": self.ioc,
            "app": self.app,
            "actions_taken": self.actions_taken,
            "acknowledged": self.acknowledged,
        }

    def one_line(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        badge = {"CRITICAL": "🔴", "HIGH": "🟠",
                 "MEDIUM": "🟡", "LOW": "🔵"}.get(self.severity, "⚪")
        actions = ", ".join(self.actions_taken) or "none"
        return f"{badge} [{self.severity}] {ts} {self.description}  → {actions}"


# ---------------------------------------------------------------------------
# Response Engine
# ---------------------------------------------------------------------------

class ResponseEngine:
    """
    Autonomous threat response — listens to all alert sources and
    executes policy-driven actions.

    Connect alert sources via:
      engine.on_ids_alert(ids_alert)
      engine.on_anomaly_alert(anomaly_alert)
      engine.on_reputation_hit(rep_entry)
      engine.on_behavior_prediction(prediction)
    """

    def __init__(self,
                 policy: PolicyEngine,
                 blocker: AutoBlocker,
                 mode: PolicyMode = PolicyMode.DEFENSIVE):
        self._policy  = policy
        self._blocker = blocker
        self._mode    = mode

        self._incidents: deque = deque(maxlen=500)
        self._incident_counter = 0
        self._flagged_apps: dict = {}        # app_name -> reason
        self._lock = threading.Lock()

        # Incident callbacks — fn(Incident)
        self._callbacks: list[Callable] = []

        # Deduplication window
        self._recent_keys: deque = deque(maxlen=200)

        # Metrics
        self._metrics = {
            "incidents_total": 0,
            "blocks_executed": 0,
            "apps_flagged": 0,
            "alerts_suppressed": 0,
        }

    # ------------------------------------------------------------------
    # Ingest from alert sources
    # ------------------------------------------------------------------

    def on_ids_alert(self, ids_alert) -> Optional[Incident]:
        """Feed an IDSAlert from the IDS engine."""
        ioc = (ids_alert.evidence or {}).get("dst_ip", "") or \
              (ids_alert.evidence or {}).get("domain", "")

        return self._handle(
            source="IDS",
            severity=ids_alert.severity,
            description=ids_alert.description,
            ioc=ioc,
            threat_type=ids_alert.category.lower(),
            evidence=ids_alert.evidence,
        )

    def on_anomaly_alert(self, anomaly_alert) -> Optional[Incident]:
        """Feed an AnomalyAlert from the AI anomaly detector."""
        return self._handle(
            source="ANOMALY",
            severity=anomaly_alert.severity,
            description=anomaly_alert.description,
            threat_type="anomaly",
            evidence={"score": anomaly_alert.score},
        )

    def on_reputation_hit(self, rep_entry) -> Optional[Incident]:
        """Feed a ReputationEntry when a malicious IOC is found."""
        if not rep_entry.is_malicious:
            return None
        ioc_type = rep_entry.ioc_type
        severity = "CRITICAL" if rep_entry.score >= 0.8 else "HIGH"
        return self._handle(
            source="REPUTATION",
            severity=severity,
            description=f"Malicious {ioc_type} detected: {rep_entry.ioc} "
                        f"(score={rep_entry.score:.2f})",
            ioc=rep_entry.ioc,
            threat_type="malicious",
            evidence=rep_entry.to_dict(),
        )

    def on_behavior_prediction(self, prediction) -> Optional[Incident]:
        """Feed a BehaviorPrediction from the malware model."""
        if prediction.risk_level not in ("HIGH", "CRITICAL"):
            return None
        return self._handle(
            source="BEHAVIOR",
            severity=prediction.risk_level,
            description=f"Malware behavior: {prediction.package_name} "
                        f"({prediction.risk_label}, p={prediction.probability_malware:.0%})",
            app=prediction.package_name,
            threat_type="malicious_app",
            evidence={"probability": prediction.probability_malware,
                      "label": prediction.risk_label},
        )

    def on_tracker_domain(self, domain: str, tracker_name: str,
                           app: str = "") -> Optional[Incident]:
        """Notify engine of a tracker domain contact."""
        return self._handle(
            source="TRACKER",
            severity="LOW",
            description=f"Tracker: {tracker_name} ({domain})",
            ioc=domain,
            app=app,
            threat_type="tracker",
        )

    # ------------------------------------------------------------------
    # Core handler
    # ------------------------------------------------------------------

    def _handle(self,
                source: str,
                severity: str,
                description: str,
                ioc: str = "",
                app: str = "",
                threat_type: str = "",
                evidence: dict = None) -> Optional[Incident]:
        """Central pipeline: evaluate → act → log → notify."""
        # Dedup check
        dedup_key = f"{source}:{ioc or description[:30]}"
        with self._lock:
            if dedup_key in self._recent_keys:
                self._metrics["alerts_suppressed"] += 1
                return None
            self._recent_keys.append(dedup_key)

        # Get policy decision
        if ioc and "." in ioc and not ioc.replace(".", "").isdigit():
            decision = self._policy.evaluate_domain(
                ioc, threat_type=threat_type, app=app,
            )
        elif ioc and ioc.replace(".", "").isdigit():
            decision = self._policy.evaluate_ip(
                ioc, threat_type=threat_type, app=app,
            )
        elif app:
            # Map severity to risk level for app evaluation
            risk_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                        "MEDIUM": "MEDIUM", "LOW": "LOW"}
            decision = self._policy.evaluate_app(
                app, risk_map.get(severity, "MEDIUM")
            )
        else:
            decision = self._policy.evaluate_anomaly(description, severity)

        actions_taken = []

        # Execute decision
        if decision.action == Action.BLOCK and ioc:
            if ioc and not self._blocker.is_blocked(ioc):
                if "." in ioc and not ioc.replace(".", "").isdigit():
                    self._blocker.block_domain(
                        ioc, reason=description,
                        source="auto", threat_type=threat_type,
                    )
                else:
                    self._blocker.block_ip(
                        ioc, reason=description,
                        source="auto", threat_type=threat_type,
                    )
                actions_taken.append(f"BLOCKED {ioc}")
                decision.auto_enforced = True
                self._metrics["blocks_executed"] += 1

        elif decision.action == Action.FLAG_APP and app:
            with self._lock:
                if app not in self._flagged_apps:
                    self._flagged_apps[app] = description
                    actions_taken.append(f"FLAGGED {app}")
                    self._metrics["apps_flagged"] += 1

        if decision.action in (Action.ALERT, Action.BLOCK, Action.FLAG_APP):
            actions_taken.insert(0, "LOGGED")

        # Build incident
        with self._lock:
            self._incident_counter += 1
            incident = Incident(
                incident_id=self._incident_counter,
                timestamp=time.time(),
                severity=severity,
                source=source,
                description=description,
                ioc=ioc,
                app=app,
                actions_taken=actions_taken,
                decision=decision,
            )
            self._incidents.append(incident)
            self._metrics["incidents_total"] += 1

        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(incident)
            except Exception:
                pass

        return incident

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def add_callback(self, fn: Callable):
        """Register fn(Incident) for all new incidents."""
        self._callbacks.append(fn)

    def get_incidents(self, limit: int = 100,
                       min_severity: str = "LOW",
                       source: str = None) -> list[Incident]:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        min_s = order.get(min_severity, 0)
        with self._lock:
            result = list(self._incidents)
        result = [i for i in result if order.get(i.severity, 0) >= min_s]
        if source:
            result = [i for i in result if i.source == source]
        return result[-limit:]

    def get_recent_incidents(self, n: int = 20) -> list[Incident]:
        with self._lock:
            return list(self._incidents)[-n:]

    def get_flagged_apps(self) -> dict:
        with self._lock:
            return dict(self._flagged_apps)

    def get_metrics(self) -> dict:
        return dict(self._metrics)

    def get_status(self) -> dict:
        mode_summary = self._policy.get_mode_summary()
        blocker_stats = self._blocker.get_stats()
        return {
            "mode": mode_summary["mode"],
            "incidents_total": self._metrics["incidents_total"],
            "blocks_executed": self._metrics["blocks_executed"],
            "apps_flagged": self._metrics["apps_flagged"],
            "blocked_domains": blocker_stats["domains_blocked"],
            "blocked_ips": blocker_stats["ips_blocked"],
            "flagged_apps": len(self._flagged_apps),
        }

    def acknowledge_incident(self, incident_id: int):
        with self._lock:
            for i in self._incidents:
                if i.incident_id == incident_id:
                    i.acknowledged = True
                    break

    def set_mode(self, mode: PolicyMode):
        self._mode = mode
        self._policy.set_mode(mode)

    def unflag_app(self, app: str):
        with self._lock:
            self._flagged_apps.pop(app, None)