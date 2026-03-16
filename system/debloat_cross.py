"""
system/debloat_cross.py

Cross-platform Debloat / Cleanup Engine.

Platform actions:
  Android   — pm disable-user / pm uninstall (bloatware, telemetry apps)
  Linux     — snap remove / apt purge / flatpak remove (known bloat packages)
  Windows   — winreg startup entries, scheduled tasks, AppX package removal
"""

import os
import sys
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Platform detection
# ─────────────────────────────────────────────────────────────────────────────

def _detect_platform() -> str:
    if os.path.exists("/data/data/com.termux"):
        return "android"
    s = platform.system().lower()
    if "windows" in s:
        return "windows"
    return "linux"


PLATFORM = _detect_platform()


# ─────────────────────────────────────────────────────────────────────────────
# Android bloatware database (from existing debloat_engine.py)
# ─────────────────────────────────────────────────────────────────────────────

ANDROID_BLOATWARE = {
    "com.samsung.android.bixby.agent":       "Samsung Bixby AI assistant",
    "com.samsung.android.bixby.wakeup":      "Bixby always-on listener",
    "com.samsung.android.game.gamehome":     "Samsung Game Launcher",
    "com.samsung.android.smartsuggestions":  "Samsung Smart Suggestions",
    "com.samsung.android.scloud":            "Samsung Cloud",
    "com.samsung.android.weather":           "Samsung Weather",
    "com.samsung.android.tvplus":            "Samsung TV Plus",
    "com.samsung.android.app.tips":          "Samsung Tips",
    "com.facebook.katana":                   "Facebook App",
    "com.facebook.services":                 "Facebook Background Services",
    "com.facebook.system":                   "Facebook System Service",
    "com.facebook.appmanager":               "Facebook App Manager",
    "com.miui.analytics":                    "Xiaomi MIUI Analytics",
    "com.xiaomi.mipicks":                    "Xiaomi GetApps",
    "com.miui.bugreport":                    "MIUI Bug Reporter",
    "com.miui.daemon":                       "MIUI Background Daemon",
    "com.huawei.appmarket":                  "Huawei AppGallery Analytics",
    "com.huawei.hitouch":                    "Huawei HiTouch",
    "com.microsoft.skydrive":               "Microsoft OneDrive",
    "com.amazon.mShop.android.shopping":    "Amazon Shopping",
    "com.netflix.partner.activation":        "Netflix Partner Activation",
    "com.ironsource.appcloud.oobe":         "ironSource App Cloud",
    "com.google.android.partnersetup":       "Google Partner Setup",
    "com.google.android.feedback":           "Google Feedback Reporter",
    "com.google.android.onetimeinitializer": "Google One-Time Initializer",
}

ANDROID_PROTECTED = frozenset({
    "android", "com.android.systemui", "com.android.phone",
    "com.android.settings", "com.android.providers.telephony",
    "com.android.providers.contacts", "com.android.providers.media",
    "com.android.server.telecom", "com.google.android.gms",
    "com.google.android.gsf", "com.android.bluetooth",
    "com.android.nfc", "com.android.keychain", "com.android.shell",
    "com.android.inputmethod.latin", "com.android.networkstack",
})


# ─────────────────────────────────────────────────────────────────────────────
# Linux bloatware database
# ─────────────────────────────────────────────────────────────────────────────

LINUX_BLOATWARE = {
    # Snap packages
    "snap:amazon":            ("snap", "Amazon shopping app"),
    "snap:spotify":           ("snap", "Spotify (snap)"),
    "snap:skype":             ("snap", "Skype (snap)"),
    "snap:gnome-characters":  ("snap", "GNOME Characters"),
    "snap:gnome-logs":        ("snap", "GNOME Logs"),
    "snap:gnome-calculator":  ("snap", "GNOME Calculator (snap)"),
    # APT packages
    "apt:gnome-games":        ("apt",  "GNOME games collection"),
    "apt:rhythmbox":          ("apt",  "Rhythmbox music player"),
    "apt:transmission-gtk":   ("apt",  "Transmission BitTorrent"),
    "apt:totem":              ("apt",  "Totem video player"),
    "apt:cheese":             ("apt",  "Cheese webcam app"),
    "apt:shotwell":           ("apt",  "Shotwell photo manager"),
    "apt:libreoffice-draw":   ("apt",  "LibreOffice Draw"),
    "apt:libreoffice-math":   ("apt",  "LibreOffice Math"),
    "apt:aisleriot":          ("apt",  "AisleRiot Solitaire"),
    "apt:gnome-mahjongg":     ("apt",  "GNOME Mahjongg"),
    "apt:gnome-mines":        ("apt",  "GNOME Mines"),
    "apt:gnome-sudoku":       ("apt",  "GNOME Sudoku"),
    "apt:quadrapassel":       ("apt",  "Quadrapassel"),
    # Flatpak
    "flatpak:org.gnome.Mines":    ("flatpak", "GNOME Mines"),
    "flatpak:org.gnome.Sudoku":   ("flatpak", "GNOME Sudoku"),
    "flatpak:org.gnome.Mahjongg": ("flatpak", "GNOME Mahjongg"),
}

# Linux startup/autorun suspicious entries to review
LINUX_AUTORUN_PATHS = [
    Path.home() / ".config/autostart",
    Path("/etc/xdg/autostart"),
    Path("/etc/init.d"),
    Path("/etc/rc.local"),
]

LINUX_TELEMETRY_SERVICES = {
    "apport":          "Ubuntu crash reporter (sends crash data)",
    "whoopsie":        "Ubuntu error reporting (sends to Canonical)",
    "fwupd":           "Firmware update daemon (network calls)",
    "snapd":           "Snap daemon (telemetry to Canonical)",
    "ubuntu-advantage": "Ubuntu Pro telemetry",
    "motd-news":       "MOTD news service (fetches remote content)",
}


# ─────────────────────────────────────────────────────────────────────────────
# Windows bloatware database
# ─────────────────────────────────────────────────────────────────────────────

WINDOWS_APPX_BLOATWARE = {
    "Microsoft.BingNews":              "Bing News app",
    "Microsoft.BingWeather":           "Bing Weather app",
    "Microsoft.BingSports":            "Bing Sports app",
    "Microsoft.BingFinance":           "Bing Finance app",
    "Microsoft.GetHelp":               "Get Help app",
    "Microsoft.Getstarted":            "Get Started / Tips",
    "Microsoft.Microsoft3DViewer":     "3D Viewer",
    "Microsoft.MicrosoftOfficeHub":    "Office Hub",
    "Microsoft.MicrosoftSolitaireCollection": "Solitaire Collection",
    "Microsoft.MixedReality.Portal":   "Mixed Reality Portal",
    "Microsoft.OneConnect":            "OneConnect / Mobile Plans",
    "Microsoft.People":                "People app",
    "Microsoft.Print3D":               "Print 3D",
    "Microsoft.SkypeApp":              "Skype UWP",
    "Microsoft.Todos":                 "Microsoft To Do",
    "Microsoft.Wallet":                "Microsoft Pay/Wallet",
    "Microsoft.WindowsFeedbackHub":    "Feedback Hub",
    "Microsoft.Xbox.TCUI":             "Xbox TCUI",
    "Microsoft.XboxApp":               "Xbox app",
    "Microsoft.XboxGameOverlay":       "Xbox Game Bar (overlay)",
    "Microsoft.XboxGamingOverlay":     "Xbox Gaming Overlay",
    "Microsoft.XboxIdentityProvider":  "Xbox Identity Provider",
    "Microsoft.XboxSpeechToTextOverlay": "Xbox Speech Overlay",
    "Microsoft.YourPhone":             "Your Phone / Phone Link",
    "Microsoft.ZuneMusic":             "Groove Music",
    "Microsoft.ZuneVideo":             "Movies & TV",
    "king.com.CandyCrushSaga":         "Candy Crush Saga",
    "king.com.CandyCrushSodaSaga":     "Candy Crush Soda",
    "Spotify.Spotify":                 "Spotify (preinstalled)",
    "Disney.37853D22215E":             "Disney+",
    "9E2F88E3.Twitter":                "Twitter/X",
}

WINDOWS_TELEMETRY_TASKS = {
    r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser":
        "Compatibility telemetry",
    r"\Microsoft\Windows\Application Experience\ProgramDataUpdater":
        "Program data telemetry",
    r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator":
        "CEIP data collector",
    r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip":
        "USB CEIP telemetry",
    r"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector":
        "Disk diagnostic data",
    r"\Microsoft\Windows\Feedback\Siuf\DmClient":
        "Feedback client",
}

WINDOWS_TELEMETRY_SERVICES = {
    "DiagTrack":    "Connected User Experiences and Telemetry (main telemetry service)",
    "dmwappushservice": "WAP Push Message Routing (telemetry helper)",
    "WSearch":      "Windows Search indexing (high disk I/O)",
    "SysMain":      "Superfetch / SysMain (RAM prefetch — may cause lag)",
    "RetailDemo":   "Retail Demo Service",
    "MapsBroker":   "Downloaded Maps Manager",
}


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DebloatItem:
    id: str
    name: str
    description: str
    platform: str
    category: str             # bloatware / telemetry / autorun / service
    risk: str = "LOW"         # risk of removing: LOW / MEDIUM / HIGH
    remove_command: str = ""
    restore_command: str = ""
    installed: bool = False
    safe_to_remove: bool = True


@dataclass
class DebloatScanResult:
    platform: str
    total_found: int = 0
    items: list = field(default_factory=list)
    telemetry_services: list = field(default_factory=list)
    autorun_entries: list = field(default_factory=list)
    scan_error: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Cross-platform engine
# ─────────────────────────────────────────────────────────────────────────────

class DebloatEngineCross:
    """
    Cross-platform bloatware scanner and remover.
    Detects — never removes without explicit user confirmation.
    """

    def __init__(self):
        self.platform = PLATFORM

    def scan(self) -> DebloatScanResult:
        result = DebloatScanResult(platform=self.platform)
        if self.platform == "android":
            return self._scan_android(result)
        elif self.platform == "linux":
            return self._scan_linux(result)
        elif self.platform == "windows":
            return self._scan_windows(result)
        result.scan_error = f"Unsupported platform: {self.platform}"
        return result

    def remove(self, item: DebloatItem,
               dry_run: bool = True) -> dict:
        """Execute removal. dry_run=True just shows the command."""
        if dry_run:
            return {"dry_run": True, "command": item.remove_command,
                    "item": item.id}
        if not item.remove_command:
            return {"success": False, "error": "No removal command"}
        try:
            r = subprocess.run(
                item.remove_command, shell=True,
                capture_output=True, text=True, timeout=30
            )
            return {
                "success": r.returncode == 0,
                "command": item.remove_command,
                "output": (r.stdout + r.stderr)[:200],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def restore(self, item: DebloatItem) -> dict:
        if not item.restore_command:
            return {"success": False, "error": "No restore command"}
        try:
            r = subprocess.run(
                item.restore_command, shell=True,
                capture_output=True, text=True, timeout=30
            )
            return {"success": r.returncode == 0,
                    "output": (r.stdout + r.stderr)[:200]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Android ───────────────────────────────────────────────────────────────

    def _scan_android(self, result: DebloatScanResult) -> DebloatScanResult:
        try:
            out = subprocess.run(
                "pm list packages", shell=True,
                capture_output=True, text=True, timeout=15
            ).stdout
            installed = {
                line[8:].strip()
                for line in out.splitlines()
                if line.startswith("package:")
            }
        except Exception:
            installed = set()

        for pkg, desc in ANDROID_BLOATWARE.items():
            if pkg in ANDROID_PROTECTED:
                continue
            item = DebloatItem(
                id=pkg, name=pkg.split(".")[-1],
                description=desc,
                platform="android",
                category="bloatware",
                risk="LOW",
                remove_command=f"pm disable-user --user 0 {pkg}",
                restore_command=f"pm enable {pkg}",
                installed=pkg in installed,
                safe_to_remove=True,
            )
            if item.installed:
                result.items.append(item)

        result.total_found = len(result.items)
        return result

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _scan_linux(self, result: DebloatScanResult) -> DebloatScanResult:
        # Snap packages
        snap_installed = self._get_snap_packages()
        # APT packages
        apt_installed  = self._get_apt_packages()
        # Flatpak
        flat_installed = self._get_flatpak_packages()

        for key, (mgr, desc) in LINUX_BLOATWARE.items():
            pkg_name = key.split(":", 1)[1]
            installed = False

            if mgr == "snap" and pkg_name in snap_installed:
                installed = True
                remove_cmd  = f"sudo snap remove {pkg_name}"
                restore_cmd = f"sudo snap install {pkg_name}"
            elif mgr == "apt" and pkg_name in apt_installed:
                installed = True
                remove_cmd  = f"sudo apt remove --purge -y {pkg_name}"
                restore_cmd = f"sudo apt install -y {pkg_name}"
            elif mgr == "flatpak" and pkg_name in flat_installed:
                installed = True
                remove_cmd  = f"flatpak uninstall -y {pkg_name}"
                restore_cmd = f"flatpak install -y {pkg_name}"
            else:
                remove_cmd = restore_cmd = ""

            if installed:
                result.items.append(DebloatItem(
                    id=key, name=pkg_name, description=desc,
                    platform="linux", category="bloatware", risk="LOW",
                    remove_command=remove_cmd, restore_command=restore_cmd,
                    installed=True, safe_to_remove=True,
                ))

        # Telemetry services
        for svc, desc in LINUX_TELEMETRY_SERVICES.items():
            status = self._linux_service_status(svc)
            if status in ("active", "enabled"):
                result.telemetry_services.append({
                    "service": svc, "description": desc,
                    "status": status,
                    "disable_cmd": f"sudo systemctl disable --now {svc}",
                    "enable_cmd":  f"sudo systemctl enable --now {svc}",
                })

        # Autorun entries
        for path in LINUX_AUTORUN_PATHS:
            if path.exists():
                for entry in path.iterdir():
                    result.autorun_entries.append({
                        "path": str(entry),
                        "name": entry.name,
                    })

        result.total_found = (len(result.items) +
                               len(result.telemetry_services))
        return result

    def _get_snap_packages(self) -> set:
        try:
            out = subprocess.run(
                "snap list 2>/dev/null", shell=True,
                capture_output=True, text=True, timeout=10
            ).stdout
            return {line.split()[0] for line in out.splitlines()[1:] if line.strip()}
        except Exception:
            return set()

    def _get_apt_packages(self) -> set:
        try:
            out = subprocess.run(
                "dpkg --get-selections 2>/dev/null", shell=True,
                capture_output=True, text=True, timeout=10
            ).stdout
            return {
                line.split()[0] for line in out.splitlines()
                if line.endswith("install")
            }
        except Exception:
            return set()

    def _get_flatpak_packages(self) -> set:
        try:
            out = subprocess.run(
                "flatpak list --app --columns=application 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=10
            ).stdout
            return {line.strip() for line in out.splitlines() if line.strip()}
        except Exception:
            return set()

    def _linux_service_status(self, service: str) -> str:
        try:
            r = subprocess.run(
                f"systemctl is-active {service} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            )
            return r.stdout.strip()
        except Exception:
            return "unknown"

    # ── Windows ───────────────────────────────────────────────────────────────

    def _scan_windows(self, result: DebloatScanResult) -> DebloatScanResult:
        # AppX packages
        installed_appx = self._get_windows_appx()
        for pkg, desc in WINDOWS_APPX_BLOATWARE.items():
            if any(pkg.lower() in p.lower() for p in installed_appx):
                result.items.append(DebloatItem(
                    id=pkg, name=pkg.split(".")[-1],
                    description=desc,
                    platform="windows", category="bloatware", risk="LOW",
                    remove_command=(
                        f'powershell -Command "Get-AppxPackage *{pkg}* '
                        f'| Remove-AppxPackage"'
                    ),
                    restore_command=(
                        f'powershell -Command "Get-AppxPackage -AllUsers '
                        f'*{pkg}* | Add-AppxPackage -DisableDevelopmentMode '
                        f'-Register \'$($_.InstallLocation)\\AppXManifest.xml\'"'
                    ),
                    installed=True,
                    safe_to_remove=True,
                ))

        # Telemetry services
        for svc, desc in WINDOWS_TELEMETRY_SERVICES.items():
            status = self._windows_service_status(svc)
            if status != "NotFound":
                result.telemetry_services.append({
                    "service": svc, "description": desc,
                    "status": status,
                    "disable_cmd": (
                        f'sc stop {svc} & sc config {svc} start=disabled'
                    ),
                    "enable_cmd": (
                        f'sc config {svc} start=auto & sc start {svc}'
                    ),
                })

        # Scheduled tasks (telemetry)
        for task, desc in WINDOWS_TELEMETRY_TASKS.items():
            if self._windows_task_exists(task):
                result.autorun_entries.append({
                    "path": task, "name": desc,
                    "disable_cmd": f'schtasks /Change /TN "{task}" /Disable',
                    "enable_cmd":  f'schtasks /Change /TN "{task}" /Enable',
                })

        result.total_found = (len(result.items) +
                               len(result.telemetry_services) +
                               len(result.autorun_entries))
        return result

    def _get_windows_appx(self) -> list:
        try:
            out = subprocess.run(
                'powershell -Command "Get-AppxPackage | Select-Object -ExpandProperty Name"',
                shell=True, capture_output=True, text=True, timeout=30
            ).stdout
            return [l.strip() for l in out.splitlines() if l.strip()]
        except Exception:
            return []

    def _windows_service_status(self, service: str) -> str:
        try:
            out = subprocess.run(
                f'sc query {service}',
                shell=True, capture_output=True, text=True, timeout=5
            ).stdout
            if "RUNNING" in out:  return "Running"
            if "STOPPED" in out:  return "Stopped"
            if "1060" in out:     return "NotFound"
            return "Unknown"
        except Exception:
            return "Unknown"

    def _windows_task_exists(self, task: str) -> bool:
        try:
            r = subprocess.run(
                f'schtasks /Query /TN "{task}"',
                shell=True, capture_output=True, timeout=5
            )
            return r.returncode == 0
        except Exception:
            return False

    # ── Report ────────────────────────────────────────────────────────────────

    def print_scan_result(self, result: DebloatScanResult):
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
            console = Console()
        except ImportError:
            print(f"\nDebloat Scan ({result.platform})")
            print(f"Found: {result.total_found} items")
            for item in result.items:
                print(f"  [{item.category}] {item.id}: {item.description}")
            return

        console.print(Panel(
            f"Platform: [bold]{result.platform.upper()}[/bold]\n"
            f"Bloatware found: [red]{len(result.items)}[/red]\n"
            f"Telemetry services: [yellow]{len(result.telemetry_services)}[/yellow]\n"
            f"Autorun entries: [dim]{len(result.autorun_entries)}[/dim]",
            title="🧹 Debloat Scan Results",
            border_style="yellow",
        ))

        if result.items:
            t = Table(title="Bloatware", show_lines=True)
            t.add_column("Package/Name", style="red", no_wrap=True)
            t.add_column("Description")
            t.add_column("Remove Command", style="dim")
            for item in result.items[:20]:
                t.add_row(item.id[:35], item.description[:35],
                          item.remove_command[:45])
            console.print(t)

        if result.telemetry_services:
            t2 = Table(title="Telemetry Services", show_lines=True)
            t2.add_column("Service", style="yellow")
            t2.add_column("Description")
            t2.add_column("Status", width=10)
            for svc in result.telemetry_services:
                t2.add_row(svc["service"], svc["description"][:40],
                           svc.get("status","?"))
            console.print(t2)