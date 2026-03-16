"""
intel/reputation_cache.py

Fast SQLite-backed reputation cache for IPs and domains.
Wraps threat_lookup.py with persistent storage.

Features:
  - TTL-based cache (configurable, default 24h)
  - Priority queue: local IOC DB checked first (zero API calls)
  - Rate limiting awareness: tracks API call counts
  - Async-friendly: uses a background worker for non-blocking lookups
  - Batch lookup with deduplication

CPU cost: Near-zero for cache hits (~μs SQLite read)
"""

import sqlite3
import json
import time
import threading
import queue
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable

DB_PATH = Path(__file__).parent.parent / "data" / "reputation_cache.db"
CACHE_TTL = 3600 * 24       # 24 hours default
NEGATIVE_TTL = 3600 * 6     # cache "clean" results for 6h


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ReputationEntry:
    ioc: str
    ioc_type: str           # ip / domain
    reputation: str         # CLEAN / SUSPICIOUS / MALICIOUS / UNKNOWN
    score: float            # 0.0–1.0
    sources: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    last_checked: float = 0.0
    ttl: float = CACHE_TTL
    raw: dict = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() - self.last_checked > self.ttl

    @property
    def is_malicious(self) -> bool:
        return self.reputation in ("MALICIOUS",) or self.score >= 0.6

    @property
    def is_suspicious(self) -> bool:
        return self.reputation in ("SUSPICIOUS",) or 0.3 <= self.score < 0.6

    def to_dict(self) -> dict:
        return {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type,
            "reputation": self.reputation,
            "score": self.score,
            "sources": self.sources,
            "tags": self.tags,
            "last_checked": self.last_checked,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ReputationEntry":
        return cls(
            ioc=d.get("ioc", ""),
            ioc_type=d.get("ioc_type", "domain"),
            reputation=d.get("reputation", "UNKNOWN"),
            score=float(d.get("score", 0.0)),
            sources=d.get("sources", []),
            tags=d.get("tags", []),
            last_checked=float(d.get("last_checked", 0.0)),
        )


# ---------------------------------------------------------------------------
# IOC Database (local, offline)
# ---------------------------------------------------------------------------

LOCAL_IOC_DB: dict[str, tuple[str, float]] = {
    # (reputation, score)
    # Known C2 / malware domains
    "malware-c2.example.com":       ("MALICIOUS", 0.95),
    "phishing-login.example.net":   ("MALICIOUS", 0.95),
    # Ad/tracking (lower severity)
    "doubleclick.net":              ("SUSPICIOUS", 0.45),
    "googlesyndication.com":        ("SUSPICIOUS", 0.40),
    "connect.facebook.net":         ("SUSPICIOUS", 0.40),
    "graph.facebook.com":           ("SUSPICIOUS", 0.35),
    "t.appsflyer.com":              ("SUSPICIOUS", 0.40),
    "api.branch.io":                ("SUSPICIOUS", 0.35),
    "app.adjust.com":               ("SUSPICIOUS", 0.38),
    "api.mixpanel.com":             ("SUSPICIOUS", 0.35),
    "api.amplitude.com":            ("SUSPICIOUS", 0.32),
    # Known safe
    "google.com":                   ("CLEAN", 0.0),
    "googleapis.com":               ("CLEAN", 0.0),
    "apple.com":                    ("CLEAN", 0.0),
    "microsoft.com":                ("CLEAN", 0.0),
    "cloudflare.com":               ("CLEAN", 0.0),
    "akamai.com":                   ("CLEAN", 0.0),
    "fastly.com":                   ("CLEAN", 0.0),
}


# ---------------------------------------------------------------------------
# Reputation Cache
# ---------------------------------------------------------------------------

class ReputationCache:
    """
    Layered reputation lookup:
      Layer 1: Local IOC DB (instant, offline)
      Layer 2: SQLite cache (fast, persistent)
      Layer 3: Remote API (via threat_lookup.py, slow, async)

    Use lookup() for synchronous (cache-first) lookups.
    Use enqueue_lookup() for non-blocking background lookups.
    """

    def __init__(self,
                 db_path: str = None,
                 cache_ttl: float = CACHE_TTL,
                 enable_remote: bool = True):
        self.db_path = str(db_path or DB_PATH)
        self.cache_ttl = cache_ttl
        self.enable_remote = enable_remote

        self._init_db()
        self._seed_local_iocs()

        # Background worker queue for async API lookups
        self._work_queue: queue.Queue = queue.Queue(maxsize=100)
        self._worker_thread = threading.Thread(
            target=self._worker_loop, daemon=True, name="rep-cache-worker"
        )
        self._worker_thread.start()

        # Callbacks triggered on async results
        self._callbacks: list[Callable] = []

        # API call counter (basic rate limiting)
        self._api_calls_today = 0
        self._api_day = int(time.time() // 86400)
        self.api_daily_limit = 200   # adjustable

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_callback(self, fn: Callable):
        """Called fn(ReputationEntry) when async lookup completes."""
        self._callbacks.append(fn)

    def lookup(self, ioc: str,
               force_refresh: bool = False) -> ReputationEntry:
        """
        Synchronous cache-first lookup.
        Returns immediately from local DB or cache.
        Does NOT hit remote API — use enqueue_lookup() for that.
        """
        ioc = ioc.strip().lower().rstrip(".")

        # Layer 1: Local IOC DB
        if not force_refresh:
            entry = self._check_local_ioc(ioc)
            if entry:
                return entry

        # Layer 2: SQLite cache
        if not force_refresh:
            entry = self._get_cached(ioc)
            if entry and not entry.is_expired:
                return entry

        # Not cached — return UNKNOWN and trigger async lookup
        self.enqueue_lookup(ioc)
        return ReputationEntry(
            ioc=ioc,
            ioc_type=self._detect_type(ioc),
            reputation="UNKNOWN",
            score=0.0,
            last_checked=0.0,
        )

    def lookup_sync(self, ioc: str) -> ReputationEntry:
        """
        Fully synchronous lookup including remote API if needed.
        Blocks until result available. Use sparingly.
        """
        entry = self.lookup(ioc)
        if entry.reputation != "UNKNOWN" and not entry.is_expired:
            return entry
        return self._do_remote_lookup(ioc)

    def enqueue_lookup(self, ioc: str, priority: bool = False):
        """Enqueue an async background lookup. Non-blocking."""
        try:
            self._work_queue.put_nowait((ioc, priority))
        except queue.Full:
            pass

    def batch_lookup(self, iocs: list[str]) -> list[ReputationEntry]:
        """Batch synchronous cache lookups (no remote calls)."""
        seen = set()
        results = []
        for ioc in iocs:
            ioc_clean = ioc.strip().lower().rstrip(".")
            if ioc_clean in seen:
                continue
            seen.add(ioc_clean)
            results.append(self.lookup(ioc_clean))
        return results

    def get_malicious(self, limit: int = 50) -> list[ReputationEntry]:
        """Return cached entries with MALICIOUS reputation."""
        return self._query_db("reputation = 'MALICIOUS' ORDER BY score DESC", limit)

    def get_suspicious(self, limit: int = 50) -> list[ReputationEntry]:
        return self._query_db("reputation = 'SUSPICIOUS' ORDER BY score DESC", limit)

    def get_stats(self) -> dict:
        try:
            with sqlite3.connect(self.db_path) as conn:
                total = conn.execute("SELECT COUNT(*) FROM reputation").fetchone()[0]
                by_rep = {}
                for row in conn.execute(
                    "SELECT reputation, COUNT(*) FROM reputation GROUP BY reputation"
                ).fetchall():
                    by_rep[row[0]] = row[1]
        except Exception:
            total = 0
            by_rep = {}

        return {
            "cached_entries": total,
            "by_reputation": by_rep,
            "queue_depth": self._work_queue.qsize(),
            "api_calls_today": self._api_calls_today,
            "api_daily_limit": self.api_daily_limit,
        }

    def add_manual_entry(self, ioc: str, reputation: str,
                          score: float, tags: list = None):
        """Add or update a manual reputation entry."""
        entry = ReputationEntry(
            ioc=ioc.lower().strip("."),
            ioc_type=self._detect_type(ioc),
            reputation=reputation,
            score=score,
            sources=["manual"],
            tags=tags or [],
            last_checked=time.time(),
        )
        self._store(entry)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _worker_loop(self):
        while True:
            try:
                ioc, _priority = self._work_queue.get(timeout=5)
                # Check if we already have a fresh result
                cached = self._get_cached(ioc)
                if cached and not cached.is_expired:
                    self._work_queue.task_done()
                    continue

                if self.enable_remote and self._api_budget_ok():
                    entry = self._do_remote_lookup(ioc)
                    if entry.reputation != "UNKNOWN":
                        for cb in self._callbacks:
                            try:
                                cb(entry)
                            except Exception:
                                pass

                self._work_queue.task_done()
            except queue.Empty:
                continue
            except Exception:
                continue

    def _do_remote_lookup(self, ioc: str) -> ReputationEntry:
        """Call threat_lookup.py for remote API check."""
        try:
            from intel.threat_lookup import ThreatLookup
            tl = ThreatLookup()
            result = tl.lookup(ioc)
            self._api_calls_today += 1

            if result.is_malicious:
                rep = "MALICIOUS"
            elif result.threat_score >= 0.3:
                rep = "SUSPICIOUS"
            elif result.sources_checked:
                rep = "CLEAN"
            else:
                rep = "UNKNOWN"

            entry = ReputationEntry(
                ioc=ioc,
                ioc_type=result.ioc_type,
                reputation=rep,
                score=result.threat_score,
                sources=result.sources_checked,
                tags=[],
                last_checked=time.time(),
                ttl=CACHE_TTL if rep != "UNKNOWN" else NEGATIVE_TTL,
                raw=result.to_dict(),
            )
            self._store(entry)
            return entry
        except Exception:
            return ReputationEntry(
                ioc=ioc,
                ioc_type=self._detect_type(ioc),
                reputation="UNKNOWN",
                score=0.0,
                last_checked=time.time(),
                ttl=NEGATIVE_TTL,
            )

    def _check_local_ioc(self, ioc: str) -> Optional[ReputationEntry]:
        """Check built-in + seeded local IOC database (instant)."""
        # Exact match
        if ioc in LOCAL_IOC_DB:
            rep, score = LOCAL_IOC_DB[ioc]
            return ReputationEntry(
                ioc=ioc,
                ioc_type=self._detect_type(ioc),
                reputation=rep,
                score=score,
                sources=["local_ioc_db"],
                last_checked=time.time(),
                ttl=float("inf"),
            )
        # Parent domain match
        parts = ioc.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in LOCAL_IOC_DB:
                rep, score = LOCAL_IOC_DB[parent]
                return ReputationEntry(
                    ioc=ioc,
                    ioc_type="domain",
                    reputation=rep,
                    score=score * 0.9,   # slightly lower confidence for subdomain
                    sources=["local_ioc_db:parent"],
                    last_checked=time.time(),
                    ttl=float("inf"),
                )
        return None

    def _get_cached(self, ioc: str) -> Optional[ReputationEntry]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT data_json FROM reputation WHERE ioc = ?", (ioc,)
                ).fetchone()
                if row:
                    return ReputationEntry.from_dict(json.loads(row[0]))
        except Exception:
            pass
        return None

    def _store(self, entry: ReputationEntry):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO reputation
                       (ioc, ioc_type, reputation, score, last_checked, data_json)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (entry.ioc, entry.ioc_type, entry.reputation,
                     entry.score, entry.last_checked,
                     json.dumps(entry.to_dict()))
                )
                conn.commit()
        except Exception:
            pass

    def _query_db(self, where: str, limit: int) -> list[ReputationEntry]:
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    f"SELECT data_json FROM reputation WHERE {where} LIMIT {limit}"
                ).fetchall()
                results = [ReputationEntry.from_dict(json.loads(r[0])) for r in rows]
        except Exception:
            pass
        return results

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reputation (
                    ioc TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    reputation TEXT,
                    score REAL,
                    last_checked REAL,
                    data_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reputation ON reputation(reputation)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_score ON reputation(score)")
            conn.commit()

    def _seed_local_iocs(self):
        """Pre-populate cache with local IOC entries."""
        for ioc, (rep, score) in LOCAL_IOC_DB.items():
            cached = self._get_cached(ioc)
            if not cached:
                self._store(ReputationEntry(
                    ioc=ioc,
                    ioc_type=self._detect_type(ioc),
                    reputation=rep,
                    score=score,
                    sources=["local_ioc_db"],
                    last_checked=time.time(),
                    ttl=float("inf"),
                ))

    def _detect_type(self, ioc: str) -> str:
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
            return "ip"
        return "domain"

    def _api_budget_ok(self) -> bool:
        today = int(time.time() // 86400)
        if today != self._api_day:
            self._api_calls_today = 0
            self._api_day = today
        return self._api_calls_today < self.api_daily_limit