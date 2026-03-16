"""
apk/installed_apk_scanner.py

Automatically scan all installed Android apps WITHOUT root.

Strategy (no root needed):
  1. `pm list packages`     → list of all installed packages
  2. `dumpsys package <pkg>` → manifest data (perms, components, SDKs)
     This gives us 80% of the intelligence we need.
  3. `pm path <pkg>`        → APK file path
  4. Try to copy APK to Termux tmp dir → DEX scan if accessible
     Works for:
       - User-installed apps  (often accessible)
       - Some system apps     (read-only but readable)
     Does NOT work for:
       - Protected system apps in /data/app (need root for DEX)
       But dumpsys still gives us manifest + permissions for those.

Result: Full analysis for user apps, manifest-only for system apps.
"""

import os
import re
import subprocess
import tempfile
import threading
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable

from apk.apk_analyzer_cross import APKAnalyzerCross
from apk.apk_static_intel import APKIntelReport, DangerousAPIHit, TrackerHit
from core.app_analyzer import AppAnalyzer, AppProfile, DANGEROUS_PERMISSIONS


# ─────────────────────────────────────────────────────────────────────────────
# Result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InstalledAPKResult:
    package_name: str
    apk_path: str = ""
    analysis_mode: str = "manifest_only"  # manifest_only | full_dex | failed
    report: Optional[APKIntelReport] = None
    profile: Optional[AppProfile] = None
    error: str = ""

    @property
    def risk_level(self) -> str:
        if self.report:
            return self.report.risk_level
        # Fallback from profile behavior flags
        if self.profile:
            from core.behavior_engine import BehaviorEngine
            eng = BehaviorEngine()
            result = eng.evaluate(self.profile)
            return result.get("level", "LOW")
        return "UNKNOWN"

    @property
    def risk_score(self) -> int:
        if self.report:
            return self.report.risk_score
        return 0

    @property
    def tracker_count(self) -> int:
        if self.report:
            return len(self.report.trackers)
        return 0

    @property
    def dangerous_perm_count(self) -> int:
        if self.report:
            return self.report.dangerous_perm_count
        if self.profile:
            return self.profile.dangerous_perm_count
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class InstalledAPKScanner:
    """
    Scans installed Android apps without root.

    For each app:
      - Always: manifest analysis via dumpsys (permissions, components)
      - If APK readable: full DEX analysis (trackers, dangerous APIs, secrets)
      - If not readable: manifest-only (still very useful)
    """

    TMP_DIR = Path("/data/data/com.termux/files/tmp/dsrp_apk_scan")

    def __init__(self,
                 include_system: bool = False,
                 max_apps: int = 50,
                 progress_callback: Optional[Callable] = None):
        self.include_system  = include_system
        self.max_apps        = max_apps
        self.progress_cb     = progress_callback
        self._analyzer       = AppAnalyzer()
        self._apk_analyser   = APKAnalyzerCross()
        self._results: list[InstalledAPKResult] = []
        self._running        = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_all(self) -> list[InstalledAPKResult]:
        """Scan all installed packages. Blocking."""
        self._running = True
        self.TMP_DIR.mkdir(parents=True, exist_ok=True)

        packages = self._analyzer.get_installed_packages(
            include_system=self.include_system)[:self.max_apps]

        results = []
        for i, pkg in enumerate(packages):
            if not self._running:
                break
            if self.progress_cb:
                self.progress_cb(i + 1, len(packages), pkg)
            result = self._scan_one(pkg)
            results.append(result)

        self._cleanup_tmp()
        self._results = results
        return results

    def scan_package(self, package_name: str) -> InstalledAPKResult:
        """Scan a single package by name."""
        return self._scan_one(package_name)

    def scan_all_async(self, done_callback: Callable):
        """Run scan in background thread."""
        def _run():
            results = self.scan_all()
            done_callback(results)
        threading.Thread(target=_run, daemon=True,
                         name="apk-scanner").start()

    def stop(self):
        self._running = False

    def get_results(self) -> list[InstalledAPKResult]:
        return list(self._results)

    def get_high_risk(self) -> list[InstalledAPKResult]:
        return [r for r in self._results
                if r.risk_level in ("HIGH", "CRITICAL")]

    # ------------------------------------------------------------------
    # Per-package scan
    # ------------------------------------------------------------------

    def _scan_one(self, pkg: str) -> InstalledAPKResult:
        result = InstalledAPKResult(package_name=pkg)

        # Step 1: Get manifest profile via dumpsys (always works)
        try:
            profile = self._analyzer.analyze_package(pkg)
            result.profile = profile
        except Exception as e:
            result.error = f"dumpsys failed: {e}"
            return result

        # Step 2: Get APK path
        apk_path = self._get_apk_path(pkg)
        result.apk_path = apk_path or ""

        if not apk_path:
            # Manifest-only analysis from profile
            result.analysis_mode = "manifest_only"
            result.report = self._build_report_from_profile(profile)
            return result

        # Step 3: Try to read APK directly
        if os.access(apk_path, os.R_OK):
            try:
                report = self._apk_analyser.analyse(apk_path)
                if not report.error:
                    # Merge profile data into report (dumpsys is more accurate for manifest)
                    self._merge_profile_into_report(profile, report)
                    result.report = report
                    result.analysis_mode = "full_dex"
                    return result
            except Exception:
                pass

        # Step 4: Try copying to tmp (sometimes works for user apps)
        tmp_path = self._try_copy_to_tmp(apk_path, pkg)
        if tmp_path:
            try:
                report = self._apk_analyser.analyse(tmp_path)
                if not report.error:
                    self._merge_profile_into_report(profile, report)
                    result.report = report
                    result.analysis_mode = "full_dex"
                    self._safe_remove(tmp_path)
                    return result
            except Exception:
                self._safe_remove(tmp_path)

        # Fallback: manifest-only
        result.analysis_mode = "manifest_only"
        result.report = self._build_report_from_profile(profile)
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_apk_path(self, pkg: str) -> Optional[str]:
        """Get APK path using pm path command."""
        try:
            out = subprocess.run(
                f"pm path {pkg}", shell=True,
                capture_output=True, text=True, timeout=5
            ).stdout.strip()
            # Output: "package:/data/app/.../base.apk"
            if out.startswith("package:"):
                return out[8:].strip()
        except Exception:
            pass

        # Fallback: parse from dumpsys
        if hasattr(self, '_analyzer') and pkg in self._analyzer._package_cache:
            profile = self._analyzer._package_cache[pkg]
            if profile.apk_path:
                return profile.apk_path

        return None

    def _try_copy_to_tmp(self, apk_path: str,
                          pkg: str) -> Optional[str]:
        """Try to copy APK to our tmp dir using various methods."""
        tmp_file = str(self.TMP_DIR / f"{pkg[:40]}.apk")

        # Method 1: Direct Python copy
        try:
            shutil.copy2(apk_path, tmp_file)
            if os.path.exists(tmp_file) and os.path.getsize(tmp_file) > 0:
                return tmp_file
        except (PermissionError, OSError):
            pass

        # Method 2: cp via shell (sometimes has different permissions)
        try:
            r = subprocess.run(
                f"cp '{apk_path}' '{tmp_file}' 2>/dev/null",
                shell=True, timeout=10
            )
            if r.returncode == 0 and os.path.exists(tmp_file):
                return tmp_file
        except Exception:
            pass

        # Method 3: run-as (for own package debug builds)
        # Not applicable for security research

        return None

    def _build_report_from_profile(self,
                                    profile: AppProfile) -> APKIntelReport:
        """Build an APKIntelReport from AppProfile (manifest-only, no DEX)."""
        from apk.apk_static_intel import APKIntelReport
        report = APKIntelReport(
            apk_path=profile.apk_path or "",
            package_name=profile.package_name,
            version_name=profile.version_name,
            version_code=profile.version_code,
        )
        report.permissions          = list(profile.permissions)
        report.dangerous_permissions= list(profile.dangerous_permissions)
        report.dangerous_perm_count = profile.dangerous_perm_count
        report.services             = list(profile.services)
        report.receivers            = list(profile.receivers)
        report.activities           = list(profile.activities)
        report.has_boot_receiver    = profile.has_boot_persistence
        report.has_accessibility    = any(
            "ACCESSIBILITY" in p for p in profile.permissions)

        # Score from manifest only
        report.risk_score, report.risk_level, report.risk_factors = \
            self._score_from_profile(profile)
        return report

    def _merge_profile_into_report(self, profile: AppProfile,
                                    report: APKIntelReport):
        """Merge accurate dumpsys data into DEX analysis report."""
        # dumpsys is more reliable for package_name and version
        if profile.package_name:
            report.package_name = profile.package_name
        if profile.version_name:
            report.version_name = profile.version_name
        if profile.version_code:
            report.version_code = profile.version_code

        # Merge permissions (union of AXML + dumpsys)
        for perm in profile.permissions:
            if perm not in report.permissions:
                report.permissions.append(perm)
        for perm in profile.dangerous_permissions:
            if perm not in report.dangerous_permissions:
                report.dangerous_permissions.append(perm)
        report.dangerous_perm_count = len(report.dangerous_permissions)
        report.has_boot_receiver = (report.has_boot_receiver or
                                     profile.has_boot_persistence)

    def _score_from_profile(self, profile: AppProfile) -> tuple[int, str, list]:
        score   = 0
        factors = []

        score += profile.dangerous_perm_count * 3

        if profile.has_sms_access and profile.has_network_access:
            score += 15
            factors.append("SMS + internet access (exfiltration risk)")
        if profile.has_mic_access and profile.has_network_access:
            score += 12
            factors.append("Microphone + internet (surveillance risk)")
        if profile.has_admin_capability:
            score += 20
            factors.append("Device admin privilege")
        if profile.has_install_capability:
            score += 12
            factors.append("Can install APKs (dropper risk)")
        if profile.has_boot_persistence and profile.has_network_access:
            score += 8
            factors.append("Boot persistence + network")
        if profile.has_camera_access and profile.has_network_access:
            score += 8
            factors.append("Camera + internet access")

        if score >= 50:   level = "CRITICAL"
        elif score >= 25: level = "HIGH"
        elif score >= 10: level = "MEDIUM"
        else:             level = "LOW"

        return score, level, factors[:5]

    def _cleanup_tmp(self):
        try:
            if self.TMP_DIR.exists():
                for f in self.TMP_DIR.iterdir():
                    self._safe_remove(str(f))
        except Exception:
            pass

    @staticmethod
    def _safe_remove(path: str):
        try:
            os.remove(path)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# CLI runner
# ─────────────────────────────────────────────────────────────────────────────

def run_installed_scan(max_apps: int = 40,
                        include_system: bool = False):
    """CLI scan of installed apps with rich output."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        from rich.panel import Panel
        console = Console()
    except ImportError:
        print("Install rich: pip install rich")
        return []

    console.print(Panel(
        f"Scanning installed apps\n"
        f"Mode: {'all packages' if include_system else 'user apps only'}\n"
        f"Limit: {max_apps} apps",
        title="[bold cyan]DSRP — Installed APK Scanner[/bold cyan]",
        border_style="cyan",
    ))

    scanned = [0]
    total   = [0]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=max_apps)

        def on_progress(current, tot, pkg):
            scanned[0] = current
            total[0]   = tot
            progress.update(task, completed=current, total=tot,
                           description=f"[dim]{pkg[:30]}[/dim]")

        scanner = InstalledAPKScanner(
            include_system=include_system,
            max_apps=max_apps,
            progress_callback=on_progress,
        )
        results = scanner.scan_all()

    # Results table
    table = Table(
        title=f"Scan Results — {len(results)} apps",
        show_lines=True,
    )
    table.add_column("Package",   style="cyan", no_wrap=True)
    table.add_column("Risk",      width=9)
    table.add_column("Score",     width=6)
    table.add_column("Mode",      width=13, style="dim")
    table.add_column("D.Perms",   width=8)
    table.add_column("Trackers",  width=9)
    table.add_column("Top Risk Factor")

    risk_colors = {
        "CRITICAL": "bold red", "HIGH": "red",
        "MEDIUM": "yellow",     "LOW":  "green",
        "UNKNOWN": "dim",
    }

    high_risk = []
    for r in sorted(results, key=lambda x: x.risk_score, reverse=True):
        level = r.risk_level
        color = risk_colors.get(level, "white")
        factor = ""
        if r.report and r.report.risk_factors:
            factor = r.report.risk_factors[0][:45]

        table.add_row(
            r.package_name[:38],
            f"[{color}]{level}[/{color}]",
            str(r.risk_score),
            r.analysis_mode[:13],
            str(r.dangerous_perm_count),
            str(r.tracker_count),
            factor,
        )
        if level in ("HIGH", "CRITICAL"):
            high_risk.append(r)

    console.print(table)

    # Summary
    full_dex   = sum(1 for r in results if r.analysis_mode == "full_dex")
    manifest   = sum(1 for r in results if r.analysis_mode == "manifest_only")

    console.print(
        f"\n[dim]Full DEX analysis: {full_dex} apps  |  "
        f"Manifest-only: {manifest} apps  |  "
        f"High/Critical: [red]{len(high_risk)}[/red][/dim]"
    )

    if high_risk:
        console.print(f"\n[bold red]⚠ {len(high_risk)} High/Critical Risk Apps:[/bold red]")
        for r in high_risk:
            console.print(f"\n  [red]{r.package_name}[/red]  "
                          f"[dim]({r.analysis_mode})[/dim]")
            if r.report:
                for factor in r.report.risk_factors[:3]:
                    console.print(f"    • {factor}")
    else:
        console.print("\n[green]✓ No high-risk apps detected.[/green]")

    return results