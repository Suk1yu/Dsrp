"""
logger.py

DSRP Logging System.
Provides a single structured logger used across all modules.

Features:
  - Rotating file handler (max 5 MB × 3 backups)
  - Coloured console output via Rich (optional)
  - Module-aware: each module gets its own child logger
  - Configurable via config.toml [logging] section
  - Silent by default if Rich not installed

Usage:
    from logger import get_logger
    log = get_logger(__name__)

    log.info("DNS monitor started")
    log.warning("Tracker detected: %s", domain)
    log.error("IDS engine failed: %s", err)
    log.debug("Feature vector: %s", vec)
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
import os
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Rich handler (optional — pretty coloured console output)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from rich.logging import RichHandler
    from rich.console import Console
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Log record format
# ─────────────────────────────────────────────────────────────────────────────

FILE_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
CONSOLE_FORMAT = "%(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# ─────────────────────────────────────────────────────────────────────────────
# Internal state
# ─────────────────────────────────────────────────────────────────────────────

_root_logger: Optional[logging.Logger] = None
_configured = False


# ─────────────────────────────────────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(
        level: str = "INFO",
        file_enabled: bool = True,
        file_path: str = "data/dsrp.log",
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 3,
        show_module: bool = True,
        console_enabled: bool = True,
) -> logging.Logger:
    """
    Initialise the DSRP root logger.
    Call once at startup (dsrp.py handles this automatically).
    """
    global _root_logger, _configured

    root = logging.getLogger("dsrp")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Prevent duplicate handlers on re-initialisation
    if root.handlers:
        root.handlers.clear()

    # ── File handler (rotating) ───────────────────────────────────────
    if file_enabled:
        log_path = Path(file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fh = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            fh.setFormatter(logging.Formatter(FILE_FORMAT, datefmt=DATE_FORMAT))
            fh.setLevel(getattr(logging, level.upper(), logging.INFO))
            root.addHandler(fh)
        except (OSError, PermissionError):
            # Can't write log file — continue without it
            pass

    # ── Console handler ───────────────────────────────────────────────
    if console_enabled:
        if _RICH_AVAILABLE:
            # Rich gives us coloured, formatted console logs
            console = Console(stderr=True)
            ch = RichHandler(
                console=console,
                show_time=True,
                show_path=show_module,
                rich_tracebacks=True,
                markup=False,
                log_time_format="[%H:%M:%S]",
            )
            ch.setLevel(logging.WARNING)  # Console only shows warnings+
        else:
            ch = logging.StreamHandler(sys.stderr)
            ch.setFormatter(
                logging.Formatter(FILE_FORMAT, datefmt=DATE_FORMAT))
            ch.setLevel(logging.WARNING)

        root.addHandler(ch)

    # Don't propagate to the root Python logger
    root.propagate = False

    _root_logger = root
    _configured = True
    return root


def _ensure_configured():
    """Auto-configure with defaults if setup_logging() was never called."""
    global _configured
    if not _configured:
        # Try to read from config system
        try:
            from config import cfg
            setup_logging(
                level=cfg.logging.level,
                file_enabled=cfg.logging.file_enabled,
                file_path=str(Path(__file__).parent / cfg.logging.file_path),
                max_bytes=cfg.logging.max_file_size_mb * 1024 * 1024,
                backup_count=cfg.logging.backup_count,
                show_module=cfg.logging.show_module,
                console_enabled=True,
            )
        except Exception:
            # Fall back to minimal setup
            setup_logging(level="INFO", file_enabled=False, console_enabled=True)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    """
    Get a module-level logger.

    name should be __name__ from the calling module, e.g.:
        log = get_logger(__name__)
        # produces logger "dsrp.network.dns_monitor"

    The full dotted name is shortened to strip the "dsrp/" prefix if present.
    """
    _ensure_configured()

    # Normalise: "network.dns_monitor" → "dsrp.network.dns_monitor"
    if name.startswith("dsrp.") or name == "dsrp":
        full_name = name
    elif "/" in name or name.endswith(".py"):
        # Called with a file path — extract module name
        parts = Path(name).with_suffix("").parts
        full_name = "dsrp." + ".".join(parts[-2:])
    else:
        full_name = f"dsrp.{name}" if not name.startswith("dsrp") else name

    return logging.getLogger(full_name)


def get_root_logger() -> logging.Logger:
    _ensure_configured()
    return logging.getLogger("dsrp")


def set_level(level: str):
    """Change log level at runtime."""
    lvl = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger("dsrp")
    root.setLevel(lvl)
    for handler in root.handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            handler.setLevel(lvl)


def get_log_path() -> Optional[Path]:
    """Return the active log file path, or None if file logging is off."""
    root = logging.getLogger("dsrp")
    for handler in root.handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            return Path(handler.baseFilename)
    return None


def get_log_stats() -> dict:
    """Return basic log file stats."""
    path = get_log_path()
    if not path or not path.exists():
        return {"file": None, "size_kb": 0, "exists": False}
    size = path.stat().st_size
    return {
        "file": str(path),
        "size_kb": round(size / 1024, 1),
        "size_mb": round(size / 1024 / 1024, 2),
        "exists": True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Convenience shortcuts (used in tight loops to avoid attribute lookup)
# ─────────────────────────────────────────────────────────────────────────────

class DSRPLogger:
    """
    Thin wrapper that adds context (stage, module) to every log line.
    Used by modules that want structured logging without boilerplate.

        log = DSRPLogger("network.dns_monitor")
        log.info("Started", poll_interval=3)
        log.warning("Tracker hit", domain="doubleclick.net")
    """

    def __init__(self, module_name: str):
        self._log = get_logger(module_name)
        self._module = module_name

    def debug(self, msg: str, **kwargs):
        extra = self._fmt(kwargs)
        self._log.debug(f"{msg}{extra}")

    def info(self, msg: str, **kwargs):
        extra = self._fmt(kwargs)
        self._log.info(f"{msg}{extra}")

    def warning(self, msg: str, **kwargs):
        extra = self._fmt(kwargs)
        self._log.warning(f"{msg}{extra}")

    def error(self, msg: str, **kwargs):
        extra = self._fmt(kwargs)
        self._log.error(f"{msg}{extra}")

    def critical(self, msg: str, **kwargs):
        extra = self._fmt(kwargs)
        self._log.critical(f"{msg}{extra}")

    def exception(self, msg: str, **kwargs):
        self._log.exception(msg)

    @staticmethod
    def _fmt(kwargs: dict) -> str:
        if not kwargs:
            return ""
        parts = [f"{k}={repr(v)}" for k, v in kwargs.items()]
        return "  [" + "  ".join(parts) + "]"