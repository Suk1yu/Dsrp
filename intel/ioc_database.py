"""
intel/ioc_database.py
Local IOC (Indicators of Compromise) database manager.
Stores and queries known malicious IPs, domains, hashes.
"""

import sqlite3
import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


DB_PATH = Path(__file__).parent.parent / "data" / "ioc_database.db"

IOC_TYPES = ["ip", "domain", "hash_md5", "hash_sha256", "url", "email"]


@dataclass
class IOCEntry:
    ioc: str
    ioc_type: str
    threat_type: str = ""
    confidence: int = 50  # 0-100
    source: str = "manual"
    tags: list = field(default_factory=list)
    added_at: float = 0.0
    last_seen: float = 0.0
    description: str = ""
    active: bool = True


# Seed IOCs — known malicious infrastructure
SEED_IOCS = [
    {"ioc": "185.220.101.0/24", "ioc_type": "ip", "threat_type": "tor_exit",
     "confidence": 90, "source": "manual", "description": "Known Tor exit nodes"},
    {"ioc": "malware-c2.example.com", "ioc_type": "domain", "threat_type": "c2",
     "confidence": 95, "source": "manual", "description": "Example C2 domain (placeholder)"},
    {"ioc": "doubleclick.net", "ioc_type": "domain", "threat_type": "tracking",
     "confidence": 80, "source": "manual", "description": "Google ad tracking"},
    {"ioc": "googlesyndication.com", "ioc_type": "domain", "threat_type": "tracking",
     "confidence": 80, "source": "manual", "description": "Google ad syndication"},
    {"ioc": "graph.facebook.com", "ioc_type": "domain", "threat_type": "tracking",
     "confidence": 70, "source": "manual", "description": "Facebook tracking endpoint"},
    {"ioc": "t.appsflyer.com", "ioc_type": "domain", "threat_type": "tracking",
     "confidence": 75, "source": "manual", "description": "AppsFlyer attribution"},
    {"ioc": "api.branch.io", "ioc_type": "domain", "threat_type": "tracking",
     "confidence": 75, "source": "manual", "description": "Branch deep linking tracker"},
    {"ioc": "api.amplitude.com", "ioc_type": "domain", "threat_type": "analytics",
     "confidence": 65, "source": "manual", "description": "Amplitude analytics"},
]


class IOCDatabase:
    """
    Local SQLite-based IOC database for fast offline lookups.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = str(db_path or DB_PATH)
        self._init_db()
        self._seed_data()

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    ioc TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    threat_type TEXT DEFAULT '',
                    confidence INTEGER DEFAULT 50,
                    source TEXT DEFAULT 'manual',
                    tags TEXT DEFAULT '[]',
                    added_at REAL,
                    last_seen REAL,
                    description TEXT DEFAULT '',
                    active INTEGER DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON iocs(threat_type)")
            conn.commit()

    def _seed_data(self):
        """Seed the database with built-in IOCs if empty."""
        count = self.count()
        if count == 0:
            for entry in SEED_IOCS:
                self.add(IOCEntry(
                    ioc=entry["ioc"],
                    ioc_type=entry["ioc_type"],
                    threat_type=entry.get("threat_type", ""),
                    confidence=entry.get("confidence", 50),
                    source=entry.get("source", "builtin"),
                    description=entry.get("description", ""),
                    added_at=time.time(),
                    last_seen=time.time(),
                ))

    def add(self, entry: IOCEntry) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO iocs
                    (ioc, ioc_type, threat_type, confidence, source,
                     tags, added_at, last_seen, description, active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.ioc, entry.ioc_type, entry.threat_type,
                    entry.confidence, entry.source,
                    json.dumps(entry.tags),
                    entry.added_at or time.time(),
                    entry.last_seen or time.time(),
                    entry.description, int(entry.active)
                ))
                conn.commit()
                return True
        except Exception:
            return False

    def lookup(self, ioc: str) -> Optional[IOCEntry]:
        """Exact lookup by IOC value."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT * FROM iocs WHERE ioc = ? AND active = 1", (ioc,)
                ).fetchone()
                if row:
                    return self._row_to_entry(row)
        except Exception:
            pass
        return None

    def lookup_domain(self, domain: str) -> Optional[IOCEntry]:
        """Lookup with parent domain fallback."""
        result = self.lookup(domain)
        if result:
            return result
        # Try parent domains
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            result = self.lookup(parent)
            if result:
                return result
        return None

    def search(self, query: str, ioc_type: str = None,
               limit: int = 50) -> list[IOCEntry]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                if ioc_type:
                    rows = conn.execute(
                        "SELECT * FROM iocs WHERE ioc LIKE ? AND ioc_type = ? LIMIT ?",
                        (f"%{query}%", ioc_type, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM iocs WHERE ioc LIKE ? LIMIT ?",
                        (f"%{query}%", limit)
                    ).fetchall()
                return [self._row_to_entry(r) for r in rows]
        except Exception:
            return []

    def get_by_threat_type(self, threat_type: str) -> list[IOCEntry]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT * FROM iocs WHERE threat_type = ? AND active = 1",
                    (threat_type,)
                ).fetchall()
                return [self._row_to_entry(r) for r in rows]
        except Exception:
            return []

    def import_from_json(self, path: str) -> int:
        """Import IOCs from a JSON file."""
        count = 0
        try:
            with open(path) as f:
                entries = json.load(f)
            for e in entries:
                entry = IOCEntry(**e)
                if self.add(entry):
                    count += 1
        except Exception:
            pass
        return count

    def export_to_json(self, path: str) -> int:
        """Export all IOCs to a JSON file."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("SELECT * FROM iocs").fetchall()
            entries = [self._row_to_entry(r).to_dict() for r in rows]
            with open(path, "w") as f:
                json.dump(entries, f, indent=2)
            return len(entries)
        except Exception:
            return 0

    def count(self) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        except Exception:
            return 0

    def _row_to_entry(self, row) -> IOCEntry:
        return IOCEntry(
            ioc=row[0], ioc_type=row[1], threat_type=row[2],
            confidence=row[3], source=row[4],
            tags=json.loads(row[5] or "[]"),
            added_at=row[6], last_seen=row[7],
            description=row[8], active=bool(row[9])
        )