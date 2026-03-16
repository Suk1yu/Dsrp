"""
system/debloat_engine.py
Detects common Android bloatware and provides safe removal guidance.
Never removes protected system packages.
"""

import subprocess
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.table import Table


PROTECTED_PACKAGES = {
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
    "com.google.android.gsf.login",
    "com.android.bluetooth",
    "com.android.nfc",
    "com.android.wifi",
    "com.android.networkstack",
    "com.android.keychain",
    "com.android.shell",
    "com.android.internal.telephony",
    "com.android.inputmethod.latin",
    "android",
}

KNOWN_BLOATWARE = {
    # Samsung
    "com.samsung.android.bixby.agent": "Samsung Bixby AI assistant",
    "com.samsung.android.game.gamehome": "Samsung Game Launcher",
    "com.samsung.android.smartsuggestions": "Samsung Smart Suggestions",
    "com.samsung.android.scloud": "Samsung Cloud",
    "com.samsung.android.weather": "Samsung Weather",
    "com.samsung.android.stock": "Samsung My Finance",
    "com.samsung.android.tvplus": "Samsung TV Plus",
    "com.samsung.android.app.tips": "Samsung Tips",
    # Facebook
    "com.facebook.katana": "Facebook App",
    "com.facebook.services": "Facebook Services (Background)",
    "com.facebook.system": "Facebook System Service",
    "com.facebook.appmanager": "Facebook App Manager",
    # Other vendor bloat
    "com.microsoft.skydrive": "OneDrive",
    "com.amazon.mShop.android.shopping": "Amazon Shopping",
    "com.netflix.partner.activation": "Netflix Partner Activation",
    "com.linkedin.android": "LinkedIn",
    "com.spotify.music": "Spotify",
    "com.gameloft.android": "Gameloft Games",
    # Xiaomi
    "com.miui.analytics": "Xiaomi Analytics",
    "com.xiaomi.mipicks": "Xiaomi GetApps",
    "com.miui.bugreport": "Xiaomi Bug Report",
    "com.miui.daemon": "Xiaomi Daemon Service",
    # Huawei
    "com.huawei.appmarket": "Huawei AppGallery",
    "com.huawei.hitouch": "Huawei HiTouch",
    # Generic ad/analytics
    "com.ironsource.appcloud.oobe": "ironSource App Cloud",
    "com.lookout": "Lookout Security",
}


@dataclass
class DebloatReport:
    package_name: str
    label: str = ""
    description: str = ""
    is_protected: bool = False
    is_system_app: bool = False
    is_known_bloatware: bool = False
    removal_method: str = "pm disable-user --user 0"
    safe_to_remove: bool = False


class DebloatEngine:
    """
    Identifies bloatware on the device and provides guided removal.
    Uses 'pm disable-user' to safely disable (not fully remove) packages.
    """

    def __init__(self):
        self.console = Console()

    def _run(self, cmd: str) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=10)
            return r.stdout.strip()
        except Exception:
            return ""

    def scan_for_bloatware(self, packages: list[str]) -> list[DebloatReport]:
        """Scan a list of packages and flag known bloatware."""
        reports = []
        for pkg in packages:
            report = DebloatReport(package_name=pkg)

            if pkg in PROTECTED_PACKAGES:
                report.is_protected = True
                report.safe_to_remove = False
                report.label = "PROTECTED"
                reports.append(report)
                continue

            if pkg in KNOWN_BLOATWARE:
                report.is_known_bloatware = True
                report.description = KNOWN_BLOATWARE[pkg]
                report.safe_to_remove = True
                report.label = "BLOATWARE"
            else:
                report.label = "OK"
                report.safe_to_remove = False

            reports.append(report)

        return reports

    def get_bloatware_list(self, packages: list[str]) -> list[DebloatReport]:
        """Return only packages identified as bloatware."""
        all_reports = self.scan_for_bloatware(packages)
        return [r for r in all_reports if r.is_known_bloatware and r.safe_to_remove]

    def generate_disable_command(self, package: str) -> Optional[str]:
        """Generate safe disable command for a package."""
        if package in PROTECTED_PACKAGES:
            return None
        return f"pm disable-user --user 0 {package}"

    def disable_package(self, package: str, dry_run: bool = True) -> dict:
        """Disable a package safely."""
        if package in PROTECTED_PACKAGES:
            return {"success": False, "reason": "PROTECTED — cannot remove"}

        cmd = self.generate_disable_command(package)
        if dry_run:
            return {
                "success": None,
                "dry_run": True,
                "command": cmd,
            }

        result = self._run(cmd)
        success = "disabled" in result.lower() or result == ""
        return {
            "success": success,
            "command": cmd,
            "output": result,
        }

    def print_bloatware_report(self, packages: list[str]):
        """Print a rich table of detected bloatware."""
        bloatware = self.get_bloatware_list(packages)
        if not bloatware:
            self.console.print("[green]No known bloatware detected.[/green]")
            return

        table = Table(title=f"Detected Bloatware [{len(bloatware)}]", show_lines=True)
        table.add_column("Package", style="cyan", no_wrap=True)
        table.add_column("Description", style="yellow")
        table.add_column("Disable Command", style="dim")

        for r in bloatware:
            table.add_row(
                r.package_name,
                r.description,
                self.generate_disable_command(r.package_name) or "N/A",
            )

        self.console.print(table)
        self.console.print(
            "\n[dim]Note: Use 'pm disable-user --user 0 <pkg>' to disable. "
            "Re-enable with 'pm enable <pkg>'.[/dim]"
        )