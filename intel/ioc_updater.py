"""
intel/ioc_updater.py

IOC database updater — pulls from public threat feeds daily.
Sources (all free, no API key required for basic feeds):
  - URLhaus (malware URLs/domains)    — abuse.ch
  - Feodo Tracker (C2 IPs)            — abuse.ch
  - OpenPhish (phishing domains)      — openphish.com
  - OISD (ad/tracker domains)         — oisd.nl

Design:
  - Updates run at most once per day
  - All data stored in local SQLite
  - Updates run in background thread
  - Graceful degradation if network unavailable

CPU cost: Minimal (one background download per day)
"""

import sqlite3
import json
import time
import threading
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

DB_PATH   = Path(__file__).parent.parent / "data" / "ioc_feeds.db"
META_PATH = Path(__file__).parent.parent / "data" / "feed_metadata.json"

UPDATE_INTERVAL = 86400.0   # 24 hours

FEEDS = {
    "urlhaus_domains": {
        "url":    "https://urlhaus.abuse.ch/downloads/text_recent/",
        "type":   "domain",
        "threat": "malware",
        "parser": "urlhaus_text",
        "limit":  2000,
    },
    "feodo_ips": {
        "url":    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type":   "ip",
        "threat": "c2_botnet",
        "parser": "comment_text",
        "limit":  2000,
    },
    "openphish_domains": {
        "url":    "https://openphish.com/feed.txt",
        "type":   "url",
        "threat": "phishing",
        "parser": "url_domain",
        "limit":  1000,
    },
}


@dataclass
class FeedUpdateResult:
    feed_name: str
    success: bool
    added: int = 0
    updated: int = 0
    skipped: int = 0
    error: str = ""
    duration_secs: float = 0.0


class IOCUpdater:
    """
    Downloads and stores IOC data from public threat feeds.
    Provides a query interface for the local IOC database.
    """

    def __init__(self, db_path: str = None,
                 update_interval: float = UPDATE_INTERVAL):
        self.db_path = str(db_path or DB_PATH)
        self.update_interval = update_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: list[Callable] = []
        self._last_update: dict = {}
        self._load_meta()
        self._init_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_callback(self, fn: Callable):
        """Called with FeedUpdateResult after each feed update."""
        self._callbacks.append(fn)

    def start_auto_update(self):
        """Start background auto-update thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._update_loop, daemon=True, name="ioc-updater"
        )
        self._thread.start()

    def stop(self):
        self._running = False

    def update_now(self, feeds: list = None) -> list[FeedUpdateResult]:
        """Run an immediate update of specified (or all) feeds."""
        target_feeds = feeds or list(FEEDS.keys())
        results = []
        for feed_name in target_feeds:
            if feed_name in FEEDS:
                result = self._update_feed(feed_name, FEEDS[feed_name])
                results.append(result)
                for cb in self._callbacks:
                    try:
                        cb(result)
                    except Exception:
                        pass
        self._save_meta()
        return results

    def check_ioc(self, ioc: str) -> Optional[dict]:
        """Check if an IP or domain is in the local IOC database."""
        ioc = ioc.strip().lower().rstrip(".")
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT ioc_type, threat_type, source, added_at "
                    "FROM iocs WHERE ioc = ?", (ioc,)
                ).fetchone()
                if row:
                    return {
                        "ioc": ioc,
                        "ioc_type": row[0],
                        "threat_type": row[1],
                        "source": row[2],
                        "added_at": row[3],
                    }
        except Exception:
            pass
        # Try parent domain
        parts = ioc.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            try:
                with sqlite3.connect(self.db_path) as conn:
                    row = conn.execute(
                        "SELECT ioc_type, threat_type, source, added_at "
                        "FROM iocs WHERE ioc = ?", (parent,)
                    ).fetchone()
                    if row:
                        return {
                            "ioc": ioc,
                            "ioc_type": row[0],
                            "threat_type": row[1],
                            "source": row[2],
                            "added_at": row[3],
                            "matched_parent": parent,
                        }
            except Exception:
                pass
        return None

    def batch_check(self, iocs: list) -> dict:
        """Check multiple IOCs. Returns {ioc: result_or_None}."""
        return {ioc: self.check_ioc(ioc) for ioc in set(iocs)}

    def get_stats(self) -> dict:
        try:
            with sqlite3.connect(self.db_path) as conn:
                total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
                by_type = {}
                for r in conn.execute(
                    "SELECT threat_type, COUNT(*) FROM iocs GROUP BY threat_type"
                ).fetchall():
                    by_type[r[0]] = r[1]
        except Exception:
            total = 0
            by_type = {}

        return {
            "total_iocs": total,
            "by_threat_type": by_type,
            "last_update": self._last_update,
            "feeds_configured": len(FEEDS),
        }

    def needs_update(self) -> bool:
        now = time.time()
        for feed_name in FEEDS:
            last = self._last_update.get(feed_name, 0)
            if now - last > self.update_interval:
                return True
        return False

    # ------------------------------------------------------------------
    # Update logic
    # ------------------------------------------------------------------

    def _update_loop(self):
        while self._running:
            if self.needs_update():
                self.update_now()
            # Sleep in small increments so stop() is responsive
            for _ in range(int(self.update_interval / 60)):
                if not self._running:
                    break
                time.sleep(60)

    def _update_feed(self, name: str, config: dict) -> FeedUpdateResult:
        if not REQUESTS_OK:
            return FeedUpdateResult(name, False, error="requests not installed")

        t0 = time.time()
        result = FeedUpdateResult(feed_name=name, success=False)

        try:
            resp = requests.get(
                config["url"],
                timeout=30,
                headers={"User-Agent": "DSRP-IOCUpdater/1.0"},
            )
            resp.raise_for_status()
            raw_text = resp.text

            iocs = self._parse(raw_text, config["parser"], config["limit"])

            added = 0
            for ioc in iocs:
                if self._store_ioc(ioc, config["type"], config["threat"], name):
                    added += 1

            self._last_update[name] = time.time()
            result.success = True
            result.added = added

        except Exception as e:
            result.error = str(e)[:80]

        result.duration_secs = round(time.time() - t0, 2)
        return result

    def _parse(self, text: str, parser: str, limit: int) -> list[str]:
        iocs = []
        lines = text.splitlines()

        if parser == "urlhaus_text":
            for line in lines:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                # Extract domain from URL
                domain = self._url_to_domain(line)
                if domain:
                    iocs.append(domain)
                if len(iocs) >= limit:
                    break

        elif parser == "comment_text":
            for line in lines:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                iocs.append(line.split()[0])
                if len(iocs) >= limit:
                    break

        elif parser == "url_domain":
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                domain = self._url_to_domain(line)
                if domain:
                    iocs.append(domain)
                if len(iocs) >= limit:
                    break

        return iocs

    @staticmethod
    def _url_to_domain(url: str) -> str:
        import re
        url = url.lower().strip()
        m = re.match(r"https?://([^/\s:?#]+)", url)
        if m:
            return m.group(1)
        # Could be raw domain
        if re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", url):
            return url
        return ""

    def _store_ioc(self, ioc: str, ioc_type: str,
                   threat_type: str, source: str) -> bool:
        if not ioc or len(ioc) > 253:
            return False
        try:
            with sqlite3.connect(self.db_path) as conn:
                existing = conn.execute(
                    "SELECT added_at FROM iocs WHERE ioc = ?", (ioc,)
                ).fetchone()
                if existing:
                    return False
                conn.execute(
                    "INSERT INTO iocs (ioc, ioc_type, threat_type, source, added_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (ioc, ioc_type, threat_type, source, time.time())
                )
                conn.commit()
                return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # DB init
    # ------------------------------------------------------------------

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    ioc TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    threat_type TEXT,
                    source TEXT,
                    added_at REAL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threat ON iocs(threat_type)")
            conn.commit()

    def _load_meta(self):
        try:
            if META_PATH.exists():
                with open(META_PATH) as f:
                    data = json.load(f)
                    self._last_update = data.get("last_update", {})
        except Exception:
            self._last_update = {}

    def _save_meta(self):
        try:
            META_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(META_PATH, "w") as f:
                json.dump({"last_update": self._last_update}, f)
        except Exception:
            pass