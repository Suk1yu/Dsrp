"""
defense/privacy_hardener.py

Privacy hardening via Android package manager (pm disable-user).
Disables known telemetry, analytics, and tracker system services.

All operations use 'pm disable-user --user 0' — reversible.
Never removes or modifies protected system packages.

Safety levels:
  SAFE     — only disable clearly non-essential analytics/trackers
  MODERATE — also disable manufacturer telemetry, background analytics
  AGGRESSIVE — disable all known telemetry (may affect some features)

CPU cost: On-demand only (runs shell commands, then idle).
"""

import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional


PROTECTED_PACKAGES = frozenset({
    "android",
    "com.android.systemui",
    "com.android.phone",
    "com.android.settings",
    "com.android.providers.telephony",
    "com.android.providers.contacts",
    "com.android.providers.media",
    "com.android.providers.calendar",
    "com.android.providers.settings",
    "com.android.server.telecom",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.bluetooth",
    "com.android.nfc",
    "com.android.keychain",
    "com.android.shell",
    "com.android.inputmethod.latin",
    "com.android.networkstack",
})


# ---------------------------------------------------------------------------
# Hardening targets database
# ---------------------------------------------------------------------------

HARDENING_TARGETS = [

    # ── Google Telemetry (SAFE) ────────────────────────────────────────
    {
        "package": "com.google.android.partnersetup",
        "label": "Google Partner Setup",
        "category": "Google Telemetry",
        "level": "SAFE",
        "description": "Device setup telemetry — not needed post-setup",
    },
    {
        "package": "com.google.android.feedback",
        "label": "Google Feedback",
        "category": "Google Telemetry",
        "level": "SAFE",
        "description": "Crash feedback reporter",
    },
    {
        "package": "com.google.android.onetimeinitializer",
        "label": "Google One-Time Initializer",
        "category": "Google Telemetry",
        "level": "SAFE",
        "description": "One-time setup telemetry",
    },
    {
        "package": "com.google.android.apps.restore",
        "label": "Google Device Restore",
        "category": "Google Services",
        "level": "SAFE",
        "description": "Device restore service (safe to disable if setup complete)",
    },

    # ── Facebook Services (SAFE) ───────────────────────────────────────
    {
        "package": "com.facebook.katana",
        "label": "Facebook App",
        "category": "Social / Tracker",
        "level": "SAFE",
        "description": "Main Facebook app with extensive tracking",
    },
    {
        "package": "com.facebook.services",
        "label": "Facebook Services",
        "category": "Social / Tracker",
        "level": "SAFE",
        "description": "Facebook background services — tracks even without using Facebook",
    },
    {
        "package": "com.facebook.system",
        "label": "Facebook System Service",
        "category": "Social / Tracker",
        "level": "SAFE",
        "description": "Facebook system-level persistence",
    },
    {
        "package": "com.facebook.appmanager",
        "label": "Facebook App Manager",
        "category": "Social / Tracker",
        "level": "SAFE",
        "description": "Manages Facebook app updates in background",
    },

    # ── Samsung Telemetry (MODERATE) ──────────────────────────────────
    {
        "package": "com.samsung.android.bixby.agent",
        "label": "Samsung Bixby",
        "category": "Samsung Telemetry",
        "level": "MODERATE",
        "description": "Samsung AI assistant with data collection",
    },
    {
        "package": "com.samsung.android.bixby.wakeup",
        "label": "Samsung Bixby Wakeup",
        "category": "Samsung Telemetry",
        "level": "MODERATE",
        "description": "Always-on Bixby listener",
    },
    {
        "package": "com.samsung.android.game.gamehome",
        "label": "Samsung Game Launcher",
        "category": "Samsung Apps",
        "level": "SAFE",
        "description": "Game launcher with analytics",
    },
    {
        "package": "com.samsung.android.smartsuggestions",
        "label": "Samsung Smart Suggestions",
        "category": "Samsung Telemetry",
        "level": "MODERATE",
        "description": "Tracks app usage to suggest content",
    },
    {
        "package": "com.samsung.android.scloud",
        "label": "Samsung Cloud",
        "category": "Samsung Telemetry",
        "level": "MODERATE",
        "description": "Samsung cloud sync with telemetry",
    },
    {
        "package": "com.samsung.android.tvplus",
        "label": "Samsung TV Plus",
        "category": "Samsung Apps",
        "level": "SAFE",
        "description": "Samsung streaming service",
    },

    # ── Xiaomi Telemetry (MODERATE) ───────────────────────────────────
    {
        "package": "com.miui.analytics",
        "label": "Xiaomi MIUI Analytics",
        "category": "Xiaomi Telemetry",
        "level": "MODERATE",
        "description": "MIUI usage analytics — significant data collection",
    },
    {
        "package": "com.xiaomi.mipicks",
        "label": "Xiaomi GetApps",
        "category": "Xiaomi Telemetry",
        "level": "SAFE",
        "description": "Xiaomi app store analytics",
    },
    {
        "package": "com.miui.daemon",
        "label": "MIUI Daemon Service",
        "category": "Xiaomi Telemetry",
        "level": "AGGRESSIVE",
        "description": "Background MIUI telemetry daemon",
    },
    {
        "package": "com.miui.bugreport",
        "label": "MIUI Bug Report",
        "category": "Xiaomi Telemetry",
        "level": "SAFE",
        "description": "Automated crash/bug reporting",
    },

    # ── Huawei Telemetry (MODERATE) ───────────────────────────────────
    {
        "package": "com.huawei.hitouch",
        "label": "Huawei HiTouch",
        "category": "Huawei Telemetry",
        "level": "SAFE",
        "description": "Huawei gesture tracking service",
    },
    {
        "package": "com.huawei.appmarket",
        "label": "Huawei AppGallery Analytics",
        "category": "Huawei Telemetry",
        "level": "MODERATE",
        "description": "AppGallery analytics tracking",
    },

    # ── Generic Analytics (AGGRESSIVE) ────────────────────────────────
    {
        "package": "com.ironsource.appcloud.oobe",
        "label": "ironSource App Cloud",
        "category": "Ad Analytics",
        "level": "AGGRESSIVE",
        "description": "ironSource ad analytics service",
    },
    {
        "package": "com.microsoft.appmanager",
        "label": "Microsoft App Manager",
        "category": "Microsoft",
        "level": "SAFE",
        "description": "Microsoft app management service",
    },
]


@dataclass
class HardeningResult:
    package: str
    label: str
    success: bool
    dry_run: bool = True
    command: str = ""
    output: str = ""
    error: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class HardeningReport:
    level: str
    total_targets: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    dry_run: bool = True
    results: list = field(default_factory=list)
    duration_secs: float = 0.0


class PrivacyHardener:
    """
    Privacy hardening via Android pm commands.
    Always dry-run by default — set dry_run=False to execute.
    """

    LEVELS = ("SAFE", "MODERATE", "AGGRESSIVE")

    def __init__(self):
        self._installed_packages: set = set()
        self._hardened: set = set()

    def get_targets(self, level: str = "SAFE") -> list[dict]:
        """Return hardening targets up to and including `level`."""
        level_idx = self.LEVELS.index(level) if level in self.LEVELS else 0
        return [t for t in HARDENING_TARGETS
                if self.LEVELS.index(t["level"]) <= level_idx]

    def preview(self, level: str = "SAFE") -> list[dict]:
        """Return targets without executing — for user review."""
        targets = self.get_targets(level)
        installed = self._get_installed_packages()
        result = []
        for t in targets:
            t_copy = dict(t)
            t_copy["installed"] = t["package"] in installed
            t_copy["command"] = f"pm disable-user --user 0 {t['package']}"
            result.append(t_copy)
        return result

    def harden(self, level: str = "SAFE",
               dry_run: bool = True) -> HardeningReport:
        """Execute hardening at the given level."""
        t0 = time.time()
        targets = self.get_targets(level)
        installed = self._get_installed_packages()
        report = HardeningReport(
            level=level,
            total_targets=len(targets),
            dry_run=dry_run,
        )

        for target in targets:
            pkg = target["package"]

            if pkg in PROTECTED_PACKAGES:
                report.skipped += 1
                continue

            if pkg in self._hardened:
                report.skipped += 1
                continue

            if pkg not in installed:
                report.skipped += 1
                continue

            cmd = f"pm disable-user --user 0 {pkg}"
            result = HardeningResult(
                package=pkg,
                label=target["label"],
                command=cmd,
                dry_run=dry_run,
                success=False,
            )

            if dry_run:
                result.success = True
                result.output = "[dry-run] would execute: " + cmd
            else:
                try:
                    out = subprocess.run(
                        cmd, shell=True, capture_output=True,
                        text=True, timeout=10
                    )
                    result.output = out.stdout.strip() or out.stderr.strip()
                    result.success = "disabled" in result.output.lower() \
                                     or out.returncode == 0
                    if result.success:
                        self._hardened.add(pkg)
                        report.succeeded += 1
                    else:
                        report.failed += 1
                        result.error = result.output[:80]
                except Exception as e:
                    result.error = str(e)[:80]
                    report.failed += 1

            if dry_run:
                report.succeeded += 1

            report.results.append(result)

        report.duration_secs = round(time.time() - t0, 2)
        return report

    def restore(self, package: str) -> bool:
        """Re-enable a previously disabled package."""
        if package in PROTECTED_PACKAGES:
            return False
        try:
            out = subprocess.run(
                f"pm enable {package}",
                shell=True, capture_output=True, text=True, timeout=10
            )
            self._hardened.discard(package)
            return out.returncode == 0
        except Exception:
            return False

    def restore_all(self) -> int:
        """Re-enable all hardened packages."""
        count = 0
        for pkg in list(self._hardened):
            if self.restore(pkg):
                count += 1
        return count

    def _get_installed_packages(self) -> set:
        try:
            out = subprocess.run(
                "pm list packages", shell=True,
                capture_output=True, text=True, timeout=10
            ).stdout
            pkgs = {line[8:].strip() for line in out.splitlines()
                    if line.startswith("package:")}
            self._installed_packages = pkgs
            return pkgs
        except Exception:
            return self._installed_packages

    def get_hardened_packages(self) -> set:
        return set(self._hardened)

    def get_level_counts(self) -> dict:
        return {
            level: sum(1 for t in HARDENING_TARGETS if t["level"] == level)
            for level in self.LEVELS
        }