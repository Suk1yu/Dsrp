"""
config.py

ASRP Configuration System.
Loads config.toml → merges environment variables → provides typed access.

Priority (highest first):
  1. Environment variables  (e.g. ASRP_DEFENSE_MODE=STRICT)
  2. config.toml            (user-edited)
  3. Built-in defaults      (hardcoded in DEFAULT_CONFIG)

Usage anywhere in the codebase:
    from config import cfg
    mode   = cfg.general.defense_mode      # "DEFENSIVE"
    vt_key = cfg.api_keys.virustotal       # "" or actual key
    cpu_t  = cfg.resources.cpu_throttle_threshold  # 75
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

ROOT = Path(__file__).parent
CONFIG_PATH = ROOT / "config.toml"

# ─────────────────────────────────────────────────────────────────────────────
# Section dataclasses — typed, IDE-friendly
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GeneralConfig:
    defense_mode: str           = "DEFENSIVE"
    dashboard_refresh_secs: int = 3
    enable_remote_intel: bool   = False
    data_dir: str               = "data"
    reports_dir: str            = "data/reports"


@dataclass
class APIKeysConfig:
    virustotal: str  = ""
    abuseipdb: str   = ""
    otx: str         = ""
    daily_api_limit: int = 200


@dataclass
class NetworkConfig:
    interface: str                  = "wlan0"
    connection_poll_interval: int   = 5
    dns_poll_interval: int          = 3
    wifi_scan_interval: int         = 120
    resolve_hostnames: bool         = True
    connection_history_size: int    = 300


@dataclass
class AIConfig:
    anomaly_analysis_interval: int  = 15
    anomaly_contamination: float    = 0.05
    anomaly_warmup_windows: int     = 20
    anomaly_retrain_interval: int   = 300
    malware_use_random_forest: bool = True
    feature_window_secs: int        = 30


@dataclass
class IDSConfig:
    port_scan_threshold: int        = 10
    port_scan_window_secs: float    = 5.0
    dns_label_length_threshold: int = 40
    dns_query_rate_threshold: int   = 80
    exfil_byte_threshold: int       = 10_000_000
    exfil_window_secs: float        = 60.0
    beaconing_min_packets: int      = 6
    beaconing_max_jitter: float     = 0.15
    alert_dedup_window_secs: int    = 30


@dataclass
class DefenseConfig:
    write_hosts_file: bool      = False
    hosts_file_path: str        = "/data/data/com.termux/files/usr/etc/hosts"
    whitelist: list             = field(default_factory=lambda: [
        "google.com", "googleapis.com", "gstatic.com",
        "apple.com", "microsoft.com", "cloudflare.com",
        "localhost", "127.0.0.1",
    ])
    block_ttl_hours: float      = 0
    auto_block_trackers: bool   = False
    response_dedup_secs: int    = 30


@dataclass
class IntelConfig:
    cache_ttl_secs: int             = 86400
    negative_ttl_secs: int          = 21600
    ioc_update_interval_secs: int   = 86400
    ioc_feed_limit: int             = 2000


@dataclass
class LoggingConfig:
    level: str           = "INFO"
    file_enabled: bool   = True
    file_path: str       = "data/dsrp.log"
    max_file_size_mb: int= 5
    backup_count: int    = 3
    show_module: bool    = True


@dataclass
class ResourcesConfig:
    cpu_throttle_threshold: int = 75
    cpu_skip_threshold: int     = 90
    max_worker_threads: int     = 3
    ram_throttle_mb: int        = 400
    ram_critical_mb: int        = 600
    monitor_interval_secs: int  = 10
    adaptive_throttling: bool   = True


# ─────────────────────────────────────────────────────────────────────────────
# Root config object
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DSRPConfig:
    general:   GeneralConfig   = field(default_factory=GeneralConfig)
    api_keys:  APIKeysConfig   = field(default_factory=APIKeysConfig)
    network:   NetworkConfig   = field(default_factory=NetworkConfig)
    ai:        AIConfig        = field(default_factory=AIConfig)
    ids:       IDSConfig       = field(default_factory=IDSConfig)
    defense:   DefenseConfig   = field(default_factory=DefenseConfig)
    intel:     IntelConfig     = field(default_factory=IntelConfig)
    logging:   LoggingConfig   = field(default_factory=LoggingConfig)
    resources: ResourcesConfig = field(default_factory=ResourcesConfig)

    # Resolved absolute paths (populated after load)
    root_dir: Path  = field(default_factory=lambda: ROOT)
    data_path: Path = field(default_factory=lambda: ROOT / "data")


# ─────────────────────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────────────────────

_ENV_PREFIX = "DSRP_"

# Maps env var suffix → (section_attr, field_attr, type)
_ENV_MAP: list[tuple] = [
    ("DEFENSE_MODE",           "general",   "defense_mode",                str),
    ("DASHBOARD_REFRESH",      "general",   "dashboard_refresh_secs",      int),
    ("ENABLE_REMOTE_INTEL",    "general",   "enable_remote_intel",         bool),
    ("VT_API_KEY",             "api_keys",  "virustotal",                  str),
    ("ABUSEIPDB_API_KEY",      "api_keys",  "abuseipdb",                   str),
    ("OTX_API_KEY",            "api_keys",  "otx",                         str),
    ("INTERFACE",              "network",   "interface",                   str),
    ("WIFI_SCAN_INTERVAL",     "network",   "wifi_scan_interval",          int),
    ("LOG_LEVEL",              "logging",   "level",                       str),
    ("CPU_THROTTLE",           "resources", "cpu_throttle_threshold",      int),
    ("RAM_THROTTLE_MB",        "resources", "ram_throttle_mb",             int),
]

# Also support legacy plain env vars (backward compat)
_LEGACY_ENV: list[tuple] = [
    ("VT_API_KEY",      "api_keys", "virustotal", str),
    ("ABUSEIPDB_API_KEY","api_keys","abuseipdb",  str),
    ("OTX_API_KEY",     "api_keys","otx",         str),
]


def _to_bool(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes", "on")


def _apply_section(section_obj, section_dict: dict):
    """Apply a dict of values onto a dataclass instance."""
    for key, value in section_dict.items():
        if hasattr(section_obj, key):
            try:
                field_type = type(getattr(section_obj, key))
                if field_type is bool and isinstance(value, str):
                    setattr(section_obj, key, _to_bool(value))
                elif field_type is list:
                    setattr(section_obj, key, value if isinstance(value, list) else [value])
                else:
                    setattr(section_obj, key, field_type(value))
            except (ValueError, TypeError):
                setattr(section_obj, key, value)


def load_config(config_path: Path = CONFIG_PATH) -> DSRPConfig:
    """
    Load and return the full DSRP configuration.
    Sources (in priority order): env vars > config.toml > defaults.
    """
    cfg = DSRPConfig()

    # ── 1. Load config.toml ───────────────────────────────────────────
    if config_path.exists():
        try:
            with open(config_path, "rb") as f:
                raw = tomllib.load(f)
            section_map = {
                "general":   cfg.general,
                "api_keys":  cfg.api_keys,
                "network":   cfg.network,
                "ai":        cfg.ai,
                "ids":       cfg.ids,
                "defense":   cfg.defense,
                "intel":     cfg.intel,
                "logging":   cfg.logging,
                "resources": cfg.resources,
            }
            for section_name, section_obj in section_map.items():
                if section_name in raw:
                    _apply_section(section_obj, raw[section_name])
        except Exception as e:
            # Config load failure is non-fatal — use defaults
            pass

    # ── 2. Apply DSRP_ prefixed environment variables ────────────────
    for suffix, section_name, field_name, cast in _ENV_MAP:
        env_key = _ENV_PREFIX + suffix
        val = os.environ.get(env_key)
        if val is not None:
            section = getattr(cfg, section_name)
            try:
                if cast is bool:
                    setattr(section, field_name, _to_bool(val))
                else:
                    setattr(section, field_name, cast(val))
            except (ValueError, TypeError):
                pass

    # ── 3. Legacy bare env vars (VT_API_KEY etc.) ────────────────────
    for env_key, section_name, field_name, cast in _LEGACY_ENV:
        val = os.environ.get(env_key)
        if val is not None:
            section = getattr(cfg, section_name)
            try:
                setattr(section, field_name, cast(val))
            except (ValueError, TypeError):
                pass

    # ── 4. Resolve paths ──────────────────────────────────────────────
    cfg.root_dir  = ROOT
    cfg.data_path = ROOT / cfg.general.data_dir
    cfg.data_path.mkdir(parents=True, exist_ok=True)
    (ROOT / cfg.general.reports_dir).mkdir(parents=True, exist_ok=True)

    # ── 5. Validate ───────────────────────────────────────────────────
    valid_modes = ("MONITOR", "DEFENSIVE", "STRICT")
    if cfg.general.defense_mode.upper() not in valid_modes:
        cfg.general.defense_mode = "DEFENSIVE"
    else:
        cfg.general.defense_mode = cfg.general.defense_mode.upper()

    valid_levels = ("DEBUG", "INFO", "WARNING", "ERROR")
    if cfg.logging.level.upper() not in valid_levels:
        cfg.logging.level = "INFO"
    else:
        cfg.logging.level = cfg.logging.level.upper()

    cfg.resources.cpu_throttle_threshold = max(
        30, min(95, cfg.resources.cpu_throttle_threshold))
    cfg.general.dashboard_refresh_secs = max(
        1, min(30, cfg.general.dashboard_refresh_secs))

    return cfg


def reload_config() -> DSRPConfig:
    """Reload config from disk and replace the global singleton."""
    global cfg
    cfg = load_config()
    return cfg


def dump_config(config: DSRPConfig) -> str:
    """Return a human-readable summary of the loaded config."""
    lines = [
        "DSRP Configuration",
        "═" * 40,
        f"  Defense mode:       {config.general.defense_mode}",
        f"  Remote intel:       {config.general.enable_remote_intel}",
        f"  VT key set:         {'yes' if config.api_keys.virustotal else 'no'}",
        f"  AbuseIPDB key set:  {'yes' if config.api_keys.abuseipdb else 'no'}",
        f"  OTX key set:        {'yes' if config.api_keys.otx else 'no'}",
        f"  Interface:          {config.network.interface}",
        f"  WiFi scan:          every {config.network.wifi_scan_interval}s",
        f"  Anomaly interval:   every {config.ai.anomaly_analysis_interval}s",
        f"  Log level:          {config.logging.level}",
        f"  Log to file:        {config.logging.file_enabled}",
        f"  CPU throttle at:    {config.resources.cpu_throttle_threshold}%",
        f"  RAM throttle at:    {config.resources.ram_throttle_mb}MB",
        f"  Data path:          {config.data_path}",
        "═" * 40,
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Global singleton — import and use anywhere
# ─────────────────────────────────────────────────────────────────────────────

cfg: DSRPConfig = load_config()