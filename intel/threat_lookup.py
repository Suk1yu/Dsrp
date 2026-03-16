"""
intel/threat_lookup.py
Checks IPs and domains against VirusTotal, AbuseIPDB, and AlienVault OTX.
Caches results in SQLite.
"""

import sqlite3
import json
import time
import hashlib
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


DB_PATH = Path(__file__).parent.parent / "data" / "threat_cache.db"

# API keys — set as environment variables
VT_API_KEY = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

CACHE_TTL = 3600 * 24  # 24 hours


@dataclass
class ThreatResult:
    ioc: str  # IP or domain
    ioc_type: str  # "ip" or "domain"
    timestamp: float = 0.0
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_total: int = 0
    vt_reputation: int = 0
    abuseipdb_score: int = 0
    abuseipdb_reports: int = 0
    otx_pulse_count: int = 0
    otx_malware_families: list = field(default_factory=list)
    is_malicious: bool = False
    threat_score: float = 0.0
    sources_checked: list = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type,
            "timestamp": self.timestamp,
            "vt_malicious": self.vt_malicious,
            "vt_suspicious": self.vt_suspicious,
            "vt_total": self.vt_total,
            "abuseipdb_score": self.abuseipdb_score,
            "otx_pulse_count": self.otx_pulse_count,
            "is_malicious": self.is_malicious,
            "threat_score": self.threat_score,
            "sources_checked": self.sources_checked,
        }


class ThreatLookup:
    """
    Orchestrates threat intelligence lookups against multiple APIs.
    Results are cached in SQLite to minimize API usage.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = str(db_path or DB_PATH)
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite cache database."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_cache (
                    ioc TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    cached_at REAL,
                    result_json TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cached_at ON threat_cache(cached_at)
            """)
            conn.commit()

    def lookup(self, ioc: str, force_refresh: bool = False) -> ThreatResult:
        """Look up an IP or domain. Returns cached result if fresh."""
        ioc = ioc.strip().lower().rstrip(".")
        ioc_type = self._detect_type(ioc)

        # Check cache
        if not force_refresh:
            cached = self._get_cached(ioc)
            if cached:
                return cached

        result = ThreatResult(ioc=ioc, ioc_type=ioc_type, timestamp=time.time())

        if not REQUESTS_AVAILABLE:
            result.error = "requests library not available"
            return result

        # VirusTotal
        if VT_API_KEY:
            self._check_virustotal(result)

        # AbuseIPDB (IP only)
        if ABUSEIPDB_API_KEY and ioc_type == "ip":
            self._check_abuseipdb(result)

        # OTX
        if OTX_API_KEY:
            self._check_otx(result)

        # Compute threat score
        result.threat_score = self._compute_score(result)
        result.is_malicious = result.threat_score >= 0.5

        # Cache result
        self._cache_result(result)
        return result

    def batch_lookup(self, iocs: list[str]) -> list[ThreatResult]:
        return [self.lookup(ioc) for ioc in iocs]

    def _detect_type(self, ioc: str) -> str:
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
            return "ip"
        return "domain"

    def _check_virustotal(self, result: ThreatResult):
        try:
            if result.ioc_type == "ip":
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{result.ioc}"
            else:
                import base64
                encoded = base64.urlsafe_b64encode(result.ioc.encode()).decode().rstrip("=")
                url = f"https://www.virustotal.com/api/v3/domains/{result.ioc}"

            headers = {"x-apikey": VT_API_KEY}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {}
                )
                result.vt_malicious = stats.get("malicious", 0)
                result.vt_suspicious = stats.get("suspicious", 0)
                result.vt_total = sum(stats.values())
                result.vt_reputation = data.get("data", {}).get(
                    "attributes", {}
                ).get("reputation", 0)
                result.sources_checked.append("VirusTotal")
        except Exception as e:
            pass

    def _check_abuseipdb(self, result: ThreatResult):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": result.ioc, "maxAgeInDays": 90}
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result.abuseipdb_score = data.get("abuseConfidenceScore", 0)
                result.abuseipdb_reports = data.get("totalReports", 0)
                result.sources_checked.append("AbuseIPDB")
        except Exception:
            pass

    def _check_otx(self, result: ThreatResult):
        try:
            if result.ioc_type == "ip":
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{result.ioc}/general"
            else:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{result.ioc}/general"

            headers = {"X-OTX-API-KEY": OTX_API_KEY}
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                result.otx_pulse_count = data.get("pulse_info", {}).get("count", 0)
                pulses = data.get("pulse_info", {}).get("pulses", [])
                families = set()
                for pulse in pulses[:5]:
                    for tag in pulse.get("tags", []):
                        families.add(tag)
                result.otx_malware_families = list(families)[:5]
                result.sources_checked.append("AlienVault OTX")
        except Exception:
            pass

    def _compute_score(self, result: ThreatResult) -> float:
        score = 0.0
        if result.vt_total > 0:
            score += 0.5 * (result.vt_malicious / max(result.vt_total, 1))
        if result.abuseipdb_score > 0:
            score += 0.3 * (result.abuseipdb_score / 100)
        if result.otx_pulse_count > 0:
            score += min(0.2, result.otx_pulse_count * 0.02)
        return min(round(score, 3), 1.0)

    def _get_cached(self, ioc: str) -> Optional[ThreatResult]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT result_json, cached_at FROM threat_cache WHERE ioc = ?", (ioc,)
                ).fetchone()
                if row:
                    cached_at = row[1]
                    if time.time() - cached_at < CACHE_TTL:
                        data = json.loads(row[0])
                        return ThreatResult(**data)
        except Exception:
            pass
        return None

    def _cache_result(self, result: ThreatResult):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO threat_cache
                       (ioc, ioc_type, cached_at, result_json) VALUES (?, ?, ?, ?)""",
                    (result.ioc, result.ioc_type, result.timestamp,
                     json.dumps(result.to_dict()))
                )
                conn.commit()
        except Exception:
            pass

    def get_cached_count(self) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                return conn.execute("SELECT COUNT(*) FROM threat_cache").fetchone()[0]
        except Exception:
            return 0

    def clear_cache(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM threat_cache")
                conn.commit()
        except Exception:
            pass