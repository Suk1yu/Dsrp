"""
defense/auto_blocker.py

Automatic domain and IP blocker.
Three blocking layers (lightest to most privileged):

  Layer 1: In-process filter  — Python set lookup, zero root
  Layer 2: Local hosts file   — /etc/hosts via Termux (needs write permission)
  Layer 3: Termux DNS hook    — override /data/data/com.termux/ resolv.conf

All blocked entries are persisted in SQLite so they survive restarts.
Unblocking is always possible.

CPU cost: O(1) per check (set lookup) — essentially zero.
"""

import sqlite3
import time
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DB_PATH      = Path(__file__).parent.parent / "data" / "blocklist.db"
HOSTS_PATH   = Path("/etc/hosts")
TERMUX_HOSTS = Path("/data/data/com.termux/files/usr/etc/hosts")

# What IP to redirect blocked domains to
BLOCK_REDIRECT_IP = "0.0.0.0"


@dataclass
class BlockEntry:
    ioc: str
    ioc_type: str        # domain / ip
    reason: str
    source: str          # auto / manual / policy
    threat_type: str = ""
    blocked_at: float = field(default_factory=time.time)
    expires_at: float = 0.0    # 0 = never expires
    is_active: bool = True

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at


@dataclass
class BlockResult:
    ioc: str
    success: bool
    method: str           # memory / hosts_file / skipped
    already_blocked: bool = False
    error: str = ""


class AutoBlocker:
    """
    Manages a layered domain/IP blocklist.

    Level 0 (always active): in-memory set — checked on every ingest_domain() call.
    Level 1 (optional):      writes to Termux hosts file.
    """

    def __init__(self, db_path: str = None,
                 write_hosts: bool = False):
        self.db_path    = str(db_path or DB_PATH)
        self.write_hosts = write_hosts

        # In-memory fast lookup sets
        self._blocked_domains: set = set()
        self._blocked_ips: set = set()
        self._lock = threading.Lock()

        self._init_db()
        self._load_from_db()

        # Stats
        self._stats = {
            "total_blocked": 0,
            "domains_blocked": 0,
            "ips_blocked": 0,
            "checks_performed": 0,
            "blocks_triggered": 0,
        }
        self._update_stats()

    # ------------------------------------------------------------------
    # Public API — check
    # ------------------------------------------------------------------

    def is_blocked(self, ioc: str) -> bool:
        """O(1) check. Call this on every domain/IP seen."""
        self._stats["checks_performed"] += 1
        ioc = ioc.lower().strip(".")
        with self._lock:
            if ioc in self._blocked_domains or ioc in self._blocked_ips:
                self._stats["blocks_triggered"] += 1
                return True
            # Parent domain check
            parts = ioc.split(".")
            for i in range(1, len(parts) - 1):
                if ".".join(parts[i:]) in self._blocked_domains:
                    self._stats["blocks_triggered"] += 1
                    return True
        return False

    def check_domain(self, domain: str) -> Optional[BlockEntry]:
        """Return the BlockEntry if blocked, else None."""
        domain = domain.lower().strip(".")
        if not self.is_blocked(domain):
            return None
        return self._get_entry(domain)

    # ------------------------------------------------------------------
    # Public API — block / unblock
    # ------------------------------------------------------------------

    def block_domain(self, domain: str, reason: str = "",
                      source: str = "auto",
                      threat_type: str = "",
                      ttl_hours: float = 0) -> BlockResult:
        """Add a domain to the blocklist."""
        domain = domain.lower().strip(".")
        if not domain or len(domain) > 253:
            return BlockResult(domain, False, "skipped", error="invalid domain")

        with self._lock:
            if domain in self._blocked_domains:
                return BlockResult(domain, True, "memory", already_blocked=True)
            self._blocked_domains.add(domain)

        expires = time.time() + ttl_hours * 3600 if ttl_hours > 0 else 0.0
        entry = BlockEntry(
            ioc=domain, ioc_type="domain",
            reason=reason or f"Blocked: {threat_type or 'policy'}",
            source=source,
            threat_type=threat_type,
            expires_at=expires,
        )
        self._persist(entry)
        self._stats["domains_blocked"] += 1
        self._stats["total_blocked"] += 1

        method = "memory"
        if self.write_hosts:
            ok = self._write_hosts_entry(domain)
            method = "hosts_file" if ok else "memory"

        return BlockResult(domain, True, method)

    def block_ip(self, ip: str, reason: str = "",
                  source: str = "auto",
                  threat_type: str = "") -> BlockResult:
        """Add an IP to the blocklist."""
        with self._lock:
            if ip in self._blocked_ips:
                return BlockResult(ip, True, "memory", already_blocked=True)
            self._blocked_ips.add(ip)

        entry = BlockEntry(
            ioc=ip, ioc_type="ip",
            reason=reason or "Blocked malicious IP",
            source=source, threat_type=threat_type,
        )
        self._persist(entry)
        self._stats["ips_blocked"] += 1
        self._stats["total_blocked"] += 1
        return BlockResult(ip, True, "memory")

    def unblock(self, ioc: str) -> bool:
        """Remove an entry from the blocklist."""
        ioc = ioc.lower().strip(".")
        with self._lock:
            self._blocked_domains.discard(ioc)
            self._blocked_ips.discard(ioc)
        self._deactivate(ioc)
        if self.write_hosts:
            self._remove_hosts_entry(ioc)
        return True

    def block_batch(self, iocs: list, reason: str = "",
                     ioc_type: str = "domain",
                     source: str = "feed",
                     threat_type: str = "") -> int:
        """Block a list of IOCs at once. Returns count added."""
        added = 0
        for ioc in iocs:
            if ioc_type == "ip":
                r = self.block_ip(ioc, reason=reason, source=source,
                                   threat_type=threat_type)
            else:
                r = self.block_domain(ioc, reason=reason, source=source,
                                       threat_type=threat_type)
            if r.success and not r.already_blocked:
                added += 1
        return added

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_blocked_domains(self, limit: int = 200) -> list[BlockEntry]:
        return self._query("ioc_type='domain' AND is_active=1 "
                           "ORDER BY blocked_at DESC", limit)

    def get_blocked_ips(self, limit: int = 100) -> list[BlockEntry]:
        return self._query("ioc_type='ip' AND is_active=1 "
                           "ORDER BY blocked_at DESC", limit)

    def get_blocked_by_type(self, threat_type: str) -> list[BlockEntry]:
        return self._query(f"threat_type='{threat_type}' AND is_active=1", 500)

    def get_stats(self) -> dict:
        self._update_stats()
        return dict(self._stats)

    def export_hosts_format(self) -> str:
        """Export current blocklist in /etc/hosts format."""
        entries = self.get_blocked_domains(limit=5000)
        lines = [
            "# DSRP Blocklist",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Entries: {len(entries)}",
            "",
        ]
        for e in entries:
            lines.append(f"{BLOCK_REDIRECT_IP}  {e.ioc}")
        return "\n".join(lines)

    def clear_expired(self) -> int:
        """Remove expired entries from memory and DB."""
        now = time.time()
        removed = 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT ioc FROM blocklist WHERE expires_at > 0 AND expires_at < ?",
                    (now,)
                ).fetchall()
                for (ioc,) in rows:
                    self.unblock(ioc)
                    removed += 1
        except Exception:
            pass
        return removed

    # ------------------------------------------------------------------
    # Hosts file helpers
    # ------------------------------------------------------------------

    def _write_hosts_entry(self, domain: str) -> bool:
        """Attempt to write to Termux or system hosts file."""
        hosts_file = TERMUX_HOSTS if TERMUX_HOSTS.exists() else HOSTS_PATH
        try:
            with open(hosts_file, "a") as f:
                f.write(f"\n{BLOCK_REDIRECT_IP}  {domain}  # DSRP blocked\n")
            return True
        except Exception:
            return False

    def _remove_hosts_entry(self, domain: str):
        hosts_file = TERMUX_HOSTS if TERMUX_HOSTS.exists() else HOSTS_PATH
        try:
            with open(hosts_file, "r") as f:
                lines = f.readlines()
            lines = [l for l in lines
                     if domain not in l or "DSRP blocked" not in l]
            with open(hosts_file, "w") as f:
                f.writelines(lines)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blocklist (
                    ioc TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    reason TEXT,
                    source TEXT,
                    threat_type TEXT,
                    blocked_at REAL,
                    expires_at REAL DEFAULT 0,
                    is_active INTEGER DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_active ON blocklist(is_active)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON blocklist(ioc_type)")
            conn.commit()

    def _load_from_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT ioc, ioc_type FROM blocklist WHERE is_active=1"
                ).fetchall()
            for ioc, ioc_type in rows:
                if ioc_type == "domain":
                    self._blocked_domains.add(ioc)
                else:
                    self._blocked_ips.add(ioc)
        except Exception:
            pass

    def _persist(self, entry: BlockEntry):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO blocklist
                    (ioc, ioc_type, reason, source, threat_type, blocked_at, expires_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """, (entry.ioc, entry.ioc_type, entry.reason, entry.source,
                      entry.threat_type, entry.blocked_at, entry.expires_at))
                conn.commit()
        except Exception:
            pass

    def _deactivate(self, ioc: str):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("UPDATE blocklist SET is_active=0 WHERE ioc=?", (ioc,))
                conn.commit()
        except Exception:
            pass

    def _get_entry(self, ioc: str) -> Optional[BlockEntry]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT * FROM blocklist WHERE ioc=?", (ioc,)
                ).fetchone()
                if row:
                    return BlockEntry(
                        ioc=row[0], ioc_type=row[1], reason=row[2],
                        source=row[3], threat_type=row[4],
                        blocked_at=row[5], expires_at=row[6],
                        is_active=bool(row[7])
                    )
        except Exception:
            pass
        return None

    def _query(self, where: str, limit: int) -> list[BlockEntry]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    f"SELECT * FROM blocklist WHERE {where} LIMIT {limit}"
                ).fetchall()
                return [BlockEntry(
                    ioc=r[0], ioc_type=r[1], reason=r[2],
                    source=r[3], threat_type=r[4],
                    blocked_at=r[5], expires_at=r[6],
                    is_active=bool(r[7])
                ) for r in rows]
        except Exception:
            return []

    def _update_stats(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM blocklist WHERE is_active=1"
                ).fetchone()[0]
                domains = conn.execute(
                    "SELECT COUNT(*) FROM blocklist WHERE is_active=1 AND ioc_type='domain'"
                ).fetchone()[0]
                ips = conn.execute(
                    "SELECT COUNT(*) FROM blocklist WHERE is_active=1 AND ioc_type='ip'"
                ).fetchone()[0]
            self._stats["total_blocked"] = total
            self._stats["domains_blocked"] = domains
            self._stats["ips_blocked"] = ips
        except Exception:
            pass