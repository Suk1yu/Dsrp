"""
network/traffic_anomaly.py
AI-based network anomaly detection using IsolationForest.
Detects: unusual packet rate, strange protocols, beaconing, DPI anomalies.
"""

import time
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


@dataclass
class AnomalyAlert:
    timestamp: float
    alert_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    src_ip: str = ""
    dst_ip: str = ""
    extra: dict = field(default_factory=dict)


class TrafficAnomalyDetector:
    """
    Sliding-window traffic analysis with IsolationForest anomaly scoring.
    Also implements rule-based detection for beaconing and DPI anomalies.
    """

    BEACONING_WINDOW = 60.0    # seconds
    BEACONING_MIN_COUNT = 5    # min packets to consider beaconing
    BEACONING_JITTER_THRESH = 0.15  # interval std/mean threshold

    def __init__(self,
                 window_size: int = 100,
                 contamination: float = 0.05,
                 retrain_interval: int = 200):
        self.window_size = window_size
        self.contamination = contamination
        self.retrain_interval = retrain_interval

        self._feature_buffer: deque = deque(maxlen=window_size)
        self._model: Optional[IsolationForest] = None
        self._packet_count = 0
        self._alerts: list[AnomalyAlert] = []
        self._last_train_count = 0

        # Beaconing tracker: dst_ip -> list of timestamps
        self._dst_timestamps: defaultdict = defaultdict(list)

        # Protocol counter
        self._proto_counts: defaultdict = defaultdict(int)
        self._proto_window: deque = deque(maxlen=200)

        # Packet rate tracker
        self._rate_window: deque = deque(maxlen=60)  # per-second counts
        self._current_second = int(time.time())
        self._current_count = 0

    def process_packet(self, record) -> list[AnomalyAlert]:
        """Feed a PacketRecord into the detector. Returns new alerts if any."""
        new_alerts = []
        now = time.time()

        # Update packet rate
        sec = int(now)
        if sec == self._current_second:
            self._current_count += 1
        else:
            self._rate_window.append(self._current_count)
            self._current_second = sec
            self._current_count = 1

        # Update beaconing tracker
        dst = getattr(record, "dst_ip", "")
        if dst:
            self._dst_timestamps[dst].append(now)
            # Prune old timestamps
            cutoff = now - self.BEACONING_WINDOW * 3
            self._dst_timestamps[dst] = [
                t for t in self._dst_timestamps[dst] if t > cutoff
            ]
            beaconing_alert = self._check_beaconing(dst)
            if beaconing_alert:
                new_alerts.append(beaconing_alert)

        # Protocol distribution
        proto = getattr(record, "protocol", "OTHER")
        self._proto_counts[proto] += 1
        self._proto_window.append(proto)

        # Build feature vector
        feat = self._build_features(record, now)
        self._feature_buffer.append(feat)
        self._packet_count += 1

        # Retrain periodically
        if (ML_AVAILABLE and
                len(self._feature_buffer) >= self.window_size and
                (self._packet_count - self._last_train_count) >= self.retrain_interval):
            self._train_model()

        # Score current packet
        if self._model and ML_AVAILABLE and len(self._feature_buffer) > 10:
            alert = self._score_packet(feat, record)
            if alert:
                new_alerts.append(alert)

        self._alerts.extend(new_alerts)
        return new_alerts

    def _build_features(self, record, now: float) -> list:
        """Extract numeric features from a packet record."""
        try:
            dst_port = getattr(record, "dst_port", 0) or 0
            src_port = getattr(record, "src_port", 0) or 0
            size = getattr(record, "size", 0) or 0
            proto_enc = {"TCP": 1, "UDP": 2, "DNS": 3, "HTTP": 4, "HTTPS": 5}.get(
                getattr(record, "protocol", "OTHER"), 0
            )
            rate = self._rate_window[-1] if self._rate_window else 0
            dst_freq = len(self._dst_timestamps.get(getattr(record, "dst_ip", ""), []))
            has_dns_query = 1 if getattr(record, "dns_query", "") else 0

            return [
                float(dst_port),
                float(src_port),
                float(size),
                float(proto_enc),
                float(rate),
                float(dst_freq),
                float(has_dns_query),
                float(now % 3600),  # time-of-day signal
            ]
        except Exception:
            return [0.0] * 8

    def _train_model(self):
        """Train/retrain IsolationForest on buffered features."""
        try:
            X = np.array(list(self._feature_buffer), dtype=float)
            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=50,
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X)
            self._last_train_count = self._packet_count
        except Exception:
            self._model = None

    def _score_packet(self, features: list, record) -> Optional[AnomalyAlert]:
        """Score a single feature vector and return alert if anomalous."""
        try:
            X = np.array([features], dtype=float)
            score = self._model.decision_function(X)[0]
            pred = self._model.predict(X)[0]  # -1 = anomaly, 1 = normal

            if pred == -1 and score < -0.2:
                severity = "HIGH" if score < -0.4 else "MEDIUM"
                return AnomalyAlert(
                    timestamp=time.time(),
                    alert_type="ML_ANOMALY",
                    severity=severity,
                    description=f"Anomalous traffic pattern detected (score={score:.3f})",
                    src_ip=getattr(record, "src_ip", ""),
                    dst_ip=getattr(record, "dst_ip", ""),
                    extra={"score": score, "port": getattr(record, "dst_port", 0)},
                )
        except Exception:
            pass
        return None

    def _check_beaconing(self, dst_ip: str) -> Optional[AnomalyAlert]:
        """Detect regular interval beaconing to a destination."""
        timestamps = self._dst_timestamps[dst_ip]
        if len(timestamps) < self.BEACONING_MIN_COUNT:
            return None

        recent = sorted(timestamps[-20:])
        intervals = [b - a for a, b in zip(recent, recent[1:])]
        if len(intervals) < 3:
            return None

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < 0.5:  # too fast — likely stream, not beacon
            return None

        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std = math.sqrt(variance)
        jitter = std / mean_interval if mean_interval > 0 else 1.0

        if jitter < self.BEACONING_JITTER_THRESH:
            # Check we haven't already alerted for this dst recently
            existing = [a for a in self._alerts[-20:]
                        if a.alert_type == "BEACONING" and a.dst_ip == dst_ip]
            if not existing:
                return AnomalyAlert(
                    timestamp=time.time(),
                    alert_type="BEACONING",
                    severity="HIGH",
                    description=(
                        f"Regular beaconing to {dst_ip} detected. "
                        f"Interval: {mean_interval:.1f}s ± {std:.2f}s — "
                        f"possible C2 communication."
                    ),
                    dst_ip=dst_ip,
                    extra={
                        "interval_mean": round(mean_interval, 2),
                        "interval_std": round(std, 2),
                        "jitter": round(jitter, 3),
                        "packet_count": len(timestamps),
                    },
                )
        return None

    def check_packet_rate_spike(self) -> Optional[AnomalyAlert]:
        """Check for sudden spike in packet rate (possible scan/flood)."""
        if len(self._rate_window) < 10:
            return None
        rates = list(self._rate_window)
        mean = sum(rates) / len(rates)
        current = rates[-1]
        if mean > 0 and current > mean * 5 and current > 20:
            return AnomalyAlert(
                timestamp=time.time(),
                alert_type="RATE_SPIKE",
                severity="MEDIUM",
                description=(
                    f"Packet rate spike: {current}/s vs avg {mean:.0f}/s — "
                    "possible scan or flood."
                ),
                extra={"current_rate": current, "avg_rate": round(mean, 1)},
            )
        return None

    def get_alerts(self, limit: int = 50) -> list[AnomalyAlert]:
        return self._alerts[-limit:]

    def get_stats(self) -> dict:
        return {
            "packets_processed": self._packet_count,
            "model_trained": self._model is not None,
            "total_alerts": len(self._alerts),
            "protocol_counts": dict(self._proto_counts),
            "tracked_destinations": len(self._dst_timestamps),
        }