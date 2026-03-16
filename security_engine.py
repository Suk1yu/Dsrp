"""
security_engine.py

Stage 3 Security Orchestrator.
Wires together:
  - Traffic feature extraction
  - AI anomaly detection (IsolationForest)
  - IDS rule engine (7 rules)
  - Malware behavior model (RandomForest)
  - Reputation cache (SQLite + remote API)

Event-driven design: modules only activate when relevant traffic is seen.
CPU target: 5–10% on mid-range ARM.
"""

import time
import threading
from pathlib import Path
from typing import Optional, Callable

from network.traffic_features import TrafficFeatureWindow, TrafficObservation
from ai.traffic_anomaly import TrafficAnomalyDetector
from ai.malware_behavior_model import MalwareBehaviorModel, AppBehaviorSnapshot
from ids.ids_engine import IDSEngine
from intel.reputation_cache import ReputationCache


# ---------------------------------------------------------------------------
# SecurityEngine
# ---------------------------------------------------------------------------

class SecurityEngine:
    """
    Central orchestrator for Stage 3 security analysis.

    Usage:
        engine = SecurityEngine()
        engine.start()

        # Feed network events
        engine.ingest_connection(conn_meta_object)
        engine.ingest_packet(packet_record_object)

        # Query results
        alerts = engine.ids.get_critical_alerts()
        anomalies = engine.anomaly.get_alerts()
    """

    def __init__(self,
                 analysis_interval: float = 15.0,
                 enable_remote_intel: bool = False):

        # --- Traffic feature window (30s rolling) ---
        self.features = TrafficFeatureWindow(window_secs=30.0)

        # --- AI anomaly detector ---
        self.anomaly = TrafficAnomalyDetector(
            feature_window=self.features,
            analysis_interval=analysis_interval,
            contamination=0.05,
        )

        # --- IDS rule engine ---
        self.ids = IDSEngine(log_to_file=True)

        # --- Malware behavior model ---
        self.behavior = MalwareBehaviorModel(use_rf=True, auto_train=True)

        # --- Reputation cache ---
        self.reputation = ReputationCache(enable_remote=enable_remote_intel)

        # --- Global alert callbacks ---
        self._alert_callbacks: list[Callable] = []
        self._lock = threading.Lock()

        # Wire IDS and anomaly alerts to unified callback
        self.ids.add_callback(self._on_ids_alert)
        self.anomaly.add_callback(self._on_anomaly_alert)
        self.reputation.add_callback(self._on_reputation_result)

        # Unified alert log
        self._all_alerts: list = []
        self._max_all_alerts = 500

        # Background DNS enrichment trigger
        self._dns_queue: list = []
        self._dns_lock = threading.Lock()

        self._running = False
        self._enrichment_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start all background threads."""
        self._running = True
        self.anomaly.start()

        self._enrichment_thread = threading.Thread(
            target=self._enrichment_loop,
            daemon=True, name="sec-enrichment"
        )
        self._enrichment_thread.start()

    def stop(self):
        self._running = False
        self.anomaly.stop()

    # ------------------------------------------------------------------
    # Ingest API
    # ------------------------------------------------------------------

    def ingest_connection(self, conn) -> list:
        """
        Feed a network connection into all relevant Stage 3 modules.
        conn: ConnectionMeta from packet_metadata.py
        """
        new_alerts = []

        # Feature window
        self.features.add_from_connection(conn)

        # IDS rule engine
        ids_alerts = self.ids.process_connection(conn)
        new_alerts.extend(ids_alerts)

        # Trigger anomaly analysis if IDS fired (event-driven)
        if ids_alerts:
            anomaly_alerts = self.anomaly.trigger_analysis()
            new_alerts.extend(anomaly_alerts)

        # Enqueue remote IP for reputation lookup
        remote_ip = getattr(conn, "remote_ip", "")
        if remote_ip:
            self.reputation.enqueue_lookup(remote_ip)

        # Track tracker connections
        hostname = getattr(conn, "remote_hostname", "")
        if hostname:
            with self._dns_lock:
                self._dns_queue.append(hostname)

        return new_alerts

    def ingest_packet(self, packet) -> list:
        """
        Feed a raw packet record into all relevant Stage 3 modules.
        packet: PacketRecord from packet_sniffer.py
        """
        new_alerts = []

        # Feature window
        obs = self.features.add_from_packet(packet)

        # IDS rule engine
        ids_alerts = self.ids.process_packet(packet)
        new_alerts.extend(ids_alerts)

        # DNS reputation enrichment
        dns_query = getattr(packet, "dns_query", "")
        if dns_query:
            self.reputation.enqueue_lookup(dns_query, priority=True)
            with self._dns_lock:
                self._dns_queue.append(dns_query)

        # Event-driven anomaly trigger on IDS match
        if ids_alerts:
            anomaly_alerts = self.anomaly.trigger_analysis()
            new_alerts.extend(anomaly_alerts)

        return new_alerts

    def analyze_app(self, profile,
                    tracker_conns: int = 0,
                    susp_ports: int = 0):
        """
        Run malware behavior model on an AppProfile.
        Returns BehaviorPrediction.
        """
        snapshot = AppBehaviorSnapshot.from_profile(
            profile, tracker_conns=tracker_conns, susp_ports=susp_ports
        )
        pred = self.behavior.predict(snapshot)

        # Cache last predictions for UI
        if not hasattr(self.behavior, "_last_predictions"):
            self.behavior._last_predictions = []
        self.behavior._last_predictions.append(pred)
        self.behavior._last_predictions = self.behavior._last_predictions[-20:]

        return pred

    def analyze_app_batch(self, profiles: list) -> list:
        """Batch app analysis."""
        return [self.analyze_app(p) for p in profiles]

    def check_reputation(self, ioc: str):
        """Synchronous cache-first reputation lookup."""
        return self.reputation.lookup(ioc)

    # ------------------------------------------------------------------
    # Unified alert interface
    # ------------------------------------------------------------------

    def add_alert_callback(self, fn: Callable):
        """Receive all alerts (IDS + anomaly) in one callback."""
        self._alert_callbacks.append(fn)

    def get_all_alerts(self, limit: int = 100) -> list:
        with self._lock:
            return list(self._all_alerts[-limit:])

    def get_status(self) -> dict:
        ids_stats    = self.ids.get_stats()
        anomaly_stat = self.anomaly.get_status()
        rep_stats    = self.reputation.get_stats()
        feat_obs     = self.features.observation_count()

        return {
            "running": self._running,
            "ids": ids_stats,
            "anomaly": anomaly_stat,
            "reputation": rep_stats,
            "feature_window_obs": feat_obs,
            "behavior_model_ready": self.behavior.trained,
            "total_alerts": len(self._all_alerts),
        }

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_ids_alert(self, alert):
        with self._lock:
            self._all_alerts.append(("IDS", alert))
            if len(self._all_alerts) > self._max_all_alerts:
                self._all_alerts.pop(0)
        for cb in self._alert_callbacks:
            try:
                cb("IDS", alert)
            except Exception:
                pass

    def _on_anomaly_alert(self, alert):
        with self._lock:
            self._all_alerts.append(("ANOMALY", alert))
            if len(self._all_alerts) > self._max_all_alerts:
                self._all_alerts.pop(0)
        for cb in self._alert_callbacks:
            try:
                cb("ANOMALY", alert)
            except Exception:
                pass

    def _on_reputation_result(self, entry):
        """Trigger IDS alert if a looked-up IOC turns out malicious."""
        if entry.is_malicious:
            # Synthesise an IDS alert for the malicious IOC
            from ids.ids_engine import IDSAlert
            alert = IDSAlert(
                alert_id=0,
                timestamp=time.time(),
                rule_id="INTEL-001",
                rule_name="Malicious IOC Detected",
                severity="HIGH",
                category="THREAT_INTEL",
                description=(
                    f"Malicious IOC: {entry.ioc} "
                    f"(score={entry.score:.2f}, sources={entry.sources})"
                ),
                evidence=entry.to_dict(),
                mitre="T1071 - Application Layer Protocol",
            )
            self._on_ids_alert(alert)

    # ------------------------------------------------------------------
    # Background enrichment
    # ------------------------------------------------------------------

    def _enrichment_loop(self):
        """Drains DNS queue and triggers batch reputation lookups."""
        while self._running:
            try:
                with self._dns_lock:
                    batch = list(set(self._dns_queue[:20]))
                    self._dns_queue.clear()

                for ioc in batch:
                    self.reputation.enqueue_lookup(ioc)

            except Exception:
                pass
            time.sleep(5)