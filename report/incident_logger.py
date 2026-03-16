"""
report/incident_logger.py

Structured incident logger.
Persists all security incidents to SQLite with rotation and export.
Also maintains a live ring buffer for UI display.

Features:
  - SQLite persistence (survives restarts)
  - Log rotation: prune entries older than MAX_AGE_DAYS
  - JSONL export for external SIEM integration
  - Severity histogram for dashboards
  - Search / filter API
"""

import sqlite3
import json
import time
from collections import deque, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DB_PATH     = Path(__file__).parent.parent / "data" / "incidents.db"
JSONL_PATH  = Path(__file__).parent.parent / "data" / "reports" / "incidents.jsonl"
MAX_AGE_DAYS = 30
MAX_DB_ENTRIES = 10_000


@dataclass
class LoggedIncident:
    incident_id: int
    timestamp: float
    severity: str
    source: str
    description: str
    ioc: str = ""
    app: str = ""
    actions: str = ""        # comma-separated
    acknowledged: bool = False

    def age_hours(self) -> float:
        return (time.time() - self.timestamp) / 3600.0

    def to_dict(self) -> dict:
        return {
            "id": self.incident_id,
            "timestamp": self.timestamp,
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(self.timestamp)),
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "ioc": self.ioc,
            "app": self.app,
            "actions": self.actions,
            "acknowledged": self.acknowledged,
        }


class IncidentLogger:
    """
    Persists and queries security incidents.
    All writes are non-blocking (synchronous but fast SQLite inserts).
    """

    def __init__(self, db_path: str = None,
                 jsonl_path: str = None,
                 max_age_days: int = MAX_AGE_DAYS):
        self.db_path      = str(db_path or DB_PATH)
        self.jsonl_path   = str(jsonl_path or JSONL_PATH)
        self.max_age_days = max_age_days

        # In-memory ring buffer for fast UI access (no DB query needed)
        self._buffer: deque = deque(maxlen=500)
        self._counter = 0

        self._init_db()
        self._load_recent()

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def log(self, incident) -> int:
        """Log an Incident object from ResponseEngine."""
        actions = ", ".join(incident.actions_taken) if incident.actions_taken else ""
        return self._write(
            severity=incident.severity,
            source=incident.source,
            description=incident.description,
            ioc=incident.ioc,
            app=incident.app,
            actions=actions,
        )

    def log_raw(self, severity: str, source: str,
                description: str, ioc: str = "",
                app: str = "", actions: str = "") -> int:
        return self._write(severity, source, description, ioc, app, actions)

    def _write(self, severity: str, source: str, description: str,
               ioc: str, app: str, actions: str) -> int:
        now = time.time()
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    INSERT INTO incidents
                    (timestamp, severity, source, description, ioc, app, actions)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (now, severity, source, description, ioc, app, actions))
                conn.commit()
                row_id = cursor.lastrowid
        except Exception:
            row_id = 0

        entry = LoggedIncident(
            incident_id=row_id,
            timestamp=now,
            severity=severity,
            source=source,
            description=description,
            ioc=ioc,
            app=app,
            actions=actions,
        )
        self._buffer.append(entry)

        # JSONL append
        try:
            Path(self.jsonl_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.jsonl_path, "a") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except Exception:
            pass

        return row_id

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def get_recent(self, n: int = 50) -> list[LoggedIncident]:
        """Fast in-memory ring buffer access."""
        return list(self._buffer)[-n:]

    def get_by_severity(self, severity: str,
                         limit: int = 100) -> list[LoggedIncident]:
        return self._query(f"severity='{severity}'", limit)

    def get_by_source(self, source: str,
                       limit: int = 100) -> list[LoggedIncident]:
        return self._query(f"source='{source}'", limit)

    def search(self, keyword: str, limit: int = 50) -> list[LoggedIncident]:
        kw = keyword.replace("'", "''")
        return self._query(
            f"(description LIKE '%{kw}%' OR ioc LIKE '%{kw}%' OR app LIKE '%{kw}%')",
            limit,
        )

    def get_since(self, since_ts: float,
                   limit: int = 500) -> list[LoggedIncident]:
        return self._query(f"timestamp >= {since_ts}", limit)

    def get_stats(self) -> dict:
        try:
            with sqlite3.connect(self.db_path) as conn:
                total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                by_sev = {}
                for r in conn.execute(
                    "SELECT severity, COUNT(*) FROM incidents GROUP BY severity"
                ).fetchall():
                    by_sev[r[0]] = r[1]
                by_src = {}
                for r in conn.execute(
                    "SELECT source, COUNT(*) FROM incidents GROUP BY source"
                ).fetchall():
                    by_src[r[0]] = r[1]
                last = conn.execute(
                    "SELECT timestamp FROM incidents ORDER BY timestamp DESC LIMIT 1"
                ).fetchone()
        except Exception:
            return {}

        return {
            "total_incidents": total,
            "by_severity": by_sev,
            "by_source": by_src,
            "last_incident": last[0] if last else None,
            "buffer_size": len(self._buffer),
        }

    def get_histogram(self, hours: int = 24,
                       bucket_hours: int = 1) -> list[dict]:
        """Return hourly incident counts for bar chart rendering."""
        now    = time.time()
        start  = now - hours * 3600
        bucket = bucket_hours * 3600

        incidents = self.get_since(start, limit=5000)
        counts: dict = {}
        for inc in incidents:
            bucket_ts = int((inc.timestamp - start) // bucket) * bucket + start
            label = time.strftime("%H:%M", time.localtime(bucket_ts))
            if label not in counts:
                counts[label] = Counter()
            counts[label][inc.severity] += 1

        return [
            {"time": k,
             "critical": v.get("CRITICAL", 0),
             "high": v.get("HIGH", 0),
             "medium": v.get("MEDIUM", 0),
             "low": v.get("LOW", 0)}
            for k, v in sorted(counts.items())
        ]

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def prune_old(self) -> int:
        """Delete entries older than max_age_days."""
        cutoff = time.time() - self.max_age_days * 86400
        try:
            with sqlite3.connect(self.db_path) as conn:
                n = conn.execute(
                    "SELECT COUNT(*) FROM incidents WHERE timestamp < ?", (cutoff,)
                ).fetchone()[0]
                conn.execute("DELETE FROM incidents WHERE timestamp < ?", (cutoff,))
                conn.commit()
                return n
        except Exception:
            return 0

    def prune_if_large(self) -> int:
        """Keep only the latest MAX_DB_ENTRIES rows."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
                if total > MAX_DB_ENTRIES:
                    excess = total - MAX_DB_ENTRIES
                    conn.execute("""
                        DELETE FROM incidents WHERE id IN (
                            SELECT id FROM incidents ORDER BY timestamp ASC LIMIT ?
                        )
                    """, (excess,))
                    conn.commit()
                    return excess
        except Exception:
            pass
        return 0

    def export_json(self, path: str, limit: int = 5000) -> int:
        entries = self.get_since(0, limit=limit)
        with open(path, "w") as f:
            json.dump([e.to_dict() for e in entries], f, indent=2)
        return len(entries)

    def acknowledge(self, incident_id: int):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE incidents SET acknowledged=1 WHERE id=?", (incident_id,)
                )
                conn.commit()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    severity TEXT,
                    source TEXT,
                    description TEXT,
                    ioc TEXT DEFAULT '',
                    app TEXT DEFAULT '',
                    actions TEXT DEFAULT '',
                    acknowledged INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON incidents(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sev ON incidents(severity)")
            conn.commit()

    def _load_recent(self):
        """Pre-fill buffer from DB."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT id,timestamp,severity,source,description,ioc,app,actions "
                    "FROM incidents ORDER BY timestamp DESC LIMIT 200"
                ).fetchall()
            for r in reversed(rows):
                self._buffer.append(LoggedIncident(
                    incident_id=r[0], timestamp=r[1], severity=r[2],
                    source=r[3], description=r[4], ioc=r[5],
                    app=r[6], actions=r[7],
                ))
        except Exception:
            pass

    def _query(self, where: str, limit: int) -> list[LoggedIncident]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    f"SELECT id,timestamp,severity,source,description,ioc,app,actions "
                    f"FROM incidents WHERE {where} ORDER BY timestamp DESC LIMIT {limit}"
                ).fetchall()
            return [LoggedIncident(
                incident_id=r[0], timestamp=r[1], severity=r[2],
                source=r[3], description=r[4], ioc=r[5],
                app=r[6], actions=r[7],
            ) for r in rows]
        except Exception:
            return []