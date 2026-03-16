"""
ai/traffic_anomaly.py

Window-based AI traffic anomaly detection.
Algorithm: IsolationForest (scikit-learn)

Design:
- Analyses 10-feature vectors extracted every `analysis_interval` seconds
- Warm-up phase: collects N windows before scoring begins
- Triggered scoring: runs immediately on suspicious event signals
- Explains anomalies using per-feature z-score deviation

CPU cost: ~3–5% (runs every 15–30s, not per-packet)
"""

import time
import threading
import math
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from network.traffic_features import (
    TrafficFeatureWindow, FeatureStats, FEATURE_NAMES, FEATURE_DIM
)


# ---------------------------------------------------------------------------
# Alert data structure
# ---------------------------------------------------------------------------

SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class AnomalyAlert:
    timestamp: float
    alert_type: str                    # ML_ANOMALY / RULE_TRIGGER / etc.
    severity: str                      # INFO / LOW / MEDIUM / HIGH / CRITICAL
    score: float                       # IsolationForest decision_function score
    description: str
    top_features: list = field(default_factory=list)  # [(feature_name, z_score)]
    triggered_by: str = ""             # which feature tripped a rule
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "score": self.score,
            "description": self.description,
            "top_features": self.top_features,
            "triggered_by": self.triggered_by,
        }

    def summary_line(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{self.severity}] {ts} {self.description}"


# ---------------------------------------------------------------------------
# Anomaly thresholds (heuristic rules run before ML)
# ---------------------------------------------------------------------------

RULE_THRESHOLDS = {
    "dns_request_rate": {
        "threshold": 60.0,   # queries/min
        "severity": "HIGH",
        "label": "High DNS Rate",
        "description": "DNS query rate {value:.0f}/min — possible DNS tunneling or C2 beacon",
    },
    "connections_per_minute": {
        "threshold": 200.0,
        "severity": "HIGH",
        "label": "Connection Flood",
        "description": "Connection rate {value:.0f}/min — possible port scan or flood",
    },
    "unique_destination_ports": {
        "threshold": 30.0,
        "severity": "HIGH",
        "label": "Port Scan",
        "description": "{value:.0f} unique ports contacted — possible port scan",
    },
    "port_entropy": {
        "threshold": 4.5,   # high entropy = many diverse ports
        "severity": "MEDIUM",
        "label": "High Port Entropy",
        "description": "Port entropy {value:.2f} — unusual port diversity",
    },
    "destination_entropy": {
        "threshold": 4.0,
        "severity": "MEDIUM",
        "label": "High Destination Entropy",
        "description": "Destination IP entropy {value:.2f} — contacting many diverse IPs",
    },
}


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

class TrafficAnomalyDetector:
    """
    AI-powered network traffic anomaly detector.

    Phase 1 — Warm-up (first `warmup_windows` windows):
        Collect baseline feature vectors. No scoring.
    Phase 2 — Baseline fit:
        Train IsolationForest on collected baseline.
    Phase 3 — Live scoring:
        Each new window scored. Alerts generated on anomaly.

    Also runs heuristic rule checks each window (no warm-up needed).
    """

    WARMUP_WINDOWS    = 20      # windows before model is ready
    ANALYSIS_INTERVAL = 15.0   # seconds between window analyses
    RETRAIN_INTERVAL  = 300.0  # retrain every 5 minutes on new data
    MAX_BASELINE_SIZE = 200     # max stored feature vectors

    def __init__(self,
                 feature_window: TrafficFeatureWindow,
                 analysis_interval: float = ANALYSIS_INTERVAL,
                 contamination: float = 0.05,
                 callbacks: list = None):
        self._fw = feature_window
        self.analysis_interval = analysis_interval
        self.contamination = contamination
        self._callbacks: list[Callable] = callbacks or []

        # Baseline buffer
        self._baseline: deque = deque(maxlen=self.MAX_BASELINE_SIZE)
        self._stats = FeatureStats()

        # Model
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[RobustScaler] = None
        self._model_trained = False
        self._last_retrain = 0.0
        self._window_count = 0

        # State
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._alerts: deque = deque(maxlen=500)

        # Dedup: suppress same alert within 60s
        self._alert_dedup: dict = {}
        self._dedup_window = 60.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_callback(self, fn: Callable):
        self._callbacks.append(fn)

    def start(self):
        """Start background analysis thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._analysis_loop, daemon=True, name="anomaly-detector"
        )
        self._thread.start()

    def stop(self):
        self._running = False

    def trigger_analysis(self) -> list[AnomalyAlert]:
        """Run an immediate analysis window (event-driven trigger)."""
        return self._analyse_window()

    def get_alerts(self, limit: int = 50,
                   min_severity: str = "LOW") -> list[AnomalyAlert]:
        min_idx = SEVERITY_LEVELS.index(min_severity) if min_severity in SEVERITY_LEVELS else 0
        result = [a for a in self._alerts
                  if SEVERITY_LEVELS.index(a.severity) >= min_idx]
        return result[-limit:]

    def get_status(self) -> dict:
        return {
            "model_trained": self._model_trained,
            "windows_collected": self._window_count,
            "warmup_remaining": max(0, self.WARMUP_WINDOWS - self._window_count),
            "total_alerts": len(self._alerts),
            "baseline_size": len(self._baseline),
            "ml_available": ML_AVAILABLE,
        }

    def is_ready(self) -> bool:
        return self._model_trained

    # ------------------------------------------------------------------
    # Analysis loop
    # ------------------------------------------------------------------

    def _analysis_loop(self):
        while self._running:
            try:
                self._analyse_window()
            except Exception:
                pass
            time.sleep(self.analysis_interval)

    def _analyse_window(self) -> list[AnomalyAlert]:
        new_alerts = []
        vec = self._fw.extract()
        if vec is None:
            return new_alerts

        self._window_count += 1
        self._stats.update(vec)
        self._baseline.append(vec)

        # --- Phase 1: Heuristic rule checks (always active) ---
        rule_alerts = self._check_rules(vec)
        new_alerts.extend(rule_alerts)

        # --- Phase 2: Train model when warmed up ---
        if (not self._model_trained and
                self._window_count >= self.WARMUP_WINDOWS and
                ML_AVAILABLE):
            self._train_model()

        # --- Periodic retraining ---
        elif (self._model_trained and
              time.time() - self._last_retrain > self.RETRAIN_INTERVAL and
              ML_AVAILABLE):
            self._train_model()

        # --- Phase 3: ML scoring ---
        if self._model_trained and ML_AVAILABLE:
            ml_alerts = self._score_vector(vec)
            new_alerts.extend(ml_alerts)

        # Dispatch
        now = time.time()
        for alert in new_alerts:
            dedup_key = f"{alert.alert_type}:{alert.triggered_by}"
            last = self._alert_dedup.get(dedup_key, 0)
            if now - last < self._dedup_window:
                continue
            self._alert_dedup[dedup_key] = now
            self._alerts.append(alert)
            for cb in self._callbacks:
                try:
                    cb(alert)
                except Exception:
                    pass

        return new_alerts

    # ------------------------------------------------------------------
    # Heuristic rules
    # ------------------------------------------------------------------

    def _check_rules(self, vec: list[float]) -> list[AnomalyAlert]:
        alerts = []
        named = dict(zip(FEATURE_NAMES, vec))

        for feature, rule in RULE_THRESHOLDS.items():
            value = named.get(feature, 0)
            if value >= rule["threshold"]:
                alert = AnomalyAlert(
                    timestamp=time.time(),
                    alert_type="RULE_TRIGGER",
                    severity=rule["severity"],
                    score=0.0,
                    description=rule["description"].format(value=value),
                    triggered_by=feature,
                    extra={"feature": feature, "value": value,
                           "threshold": rule["threshold"]},
                )
                alerts.append(alert)

        # Composite: beaconing candidate (low dest diversity + high rate)
        conn_pm = named.get("connections_per_minute", 0)
        uniq_ips = named.get("unique_destination_ips", 0)
        if conn_pm > 30 and uniq_ips <= 2 and conn_pm > 0:
            alerts.append(AnomalyAlert(
                timestamp=time.time(),
                alert_type="BEACONING_CANDIDATE",
                severity="HIGH",
                score=0.0,
                description=(
                    f"Possible C2 beaconing: {conn_pm:.0f} conn/min to only "
                    f"{uniq_ips} IPs — regular check-in pattern"
                ),
                triggered_by="beaconing_composite",
            ))

        return alerts

    # ------------------------------------------------------------------
    # ML training and scoring
    # ------------------------------------------------------------------

    def _train_model(self):
        if not ML_AVAILABLE or len(self._baseline) < 10:
            return
        try:
            X = np.array(list(self._baseline), dtype=float)
            self._scaler = RobustScaler()
            X_scaled = self._scaler.fit_transform(X)
            self._model = IsolationForest(
                n_estimators=80,
                contamination=self.contamination,
                max_samples=min(len(X), 128),
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X_scaled)
            self._model_trained = True
            self._last_retrain = time.time()
        except Exception:
            pass

    def _score_vector(self, vec: list[float]) -> list[AnomalyAlert]:
        try:
            X = np.array([vec], dtype=float)
            X_scaled = self._scaler.transform(X)
            score = float(self._model.decision_function(X_scaled)[0])
            pred  = int(self._model.predict(X_scaled)[0])   # -1 = anomaly

            if pred != -1:
                return []

            # Severity by score depth
            if score < -0.5:
                severity = "CRITICAL"
            elif score < -0.35:
                severity = "HIGH"
            elif score < -0.2:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            # Explain: which features deviate most from baseline
            zscores = self._stats.zscore(vec)
            top_features = sorted(
                zip(FEATURE_NAMES, zscores),
                key=lambda x: abs(x[1]), reverse=True
            )[:3]
            top_features = [(n, round(z, 2)) for n, z in top_features
                            if abs(z) > 1.5]

            # Human-readable reason
            reason = self._explain_anomaly(vec, top_features)

            return [AnomalyAlert(
                timestamp=time.time(),
                alert_type="ML_ANOMALY",
                severity=severity,
                score=round(score, 4),
                description=reason,
                top_features=top_features,
                triggered_by="isolation_forest",
                extra={"score": score, "prediction": pred},
            )]
        except Exception:
            return []

    def _explain_anomaly(self, vec: list[float],
                          top_features: list) -> str:
        named = dict(zip(FEATURE_NAMES, vec))
        reasons = []

        for fname, zscore in top_features:
            val = named.get(fname, 0)
            label = fname.replace("_", " ")
            if zscore > 0:
                reasons.append(f"unusually high {label} ({val:.1f})")
            else:
                reasons.append(f"unusually low {label} ({val:.1f})")

        if not reasons:
            reasons = ["statistical outlier detected in traffic pattern"]

        # Map to human interpretations
        interpretations = []
        for fname, _ in top_features:
            if fname == "dns_request_rate":
                interpretations.append("DNS tunneling or C2 beaconing")
            elif fname in ("connections_per_minute", "unique_destination_ports"):
                interpretations.append("port scan or network flood")
            elif fname == "destination_entropy":
                interpretations.append("botnet-style scanning")
            elif fname == "port_entropy":
                interpretations.append("service enumeration")

        desc = "ML anomaly detected: " + "; ".join(reasons[:2])
        if interpretations:
            desc += f" — possible: {interpretations[0]}"
        return desc