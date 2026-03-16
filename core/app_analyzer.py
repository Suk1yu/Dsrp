"""
core/app_analyzer.py
Scans installed Android applications using Termux shell commands.
Extracts permissions, services, receivers, and risk indicators.
"""

import subprocess
import re
import json
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.INTERNET",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.SCHEDULE_EXACT_ALARM",
    "android.permission.USE_EXACT_ALARM",
}


@dataclass
class AppProfile:
    package_name: str
    app_label: str = ""
    version_name: str = ""
    version_code: str = ""
    install_date: str = ""
    first_install: str = ""
    last_update: str = ""
    target_sdk: int = 0
    min_sdk: int = 0
    permissions: list = field(default_factory=list)
    dangerous_permissions: list = field(default_factory=list)
    dangerous_perm_count: int = 0
    services: list = field(default_factory=list)
    receivers: list = field(default_factory=list)
    providers: list = field(default_factory=list)
    activities: list = field(default_factory=list)
    has_boot_persistence: bool = False
    has_background_service: bool = False
    has_network_access: bool = False
    has_sms_access: bool = False
    has_mic_access: bool = False
    has_camera_access: bool = False
    has_location_access: bool = False
    has_contact_access: bool = False
    has_install_capability: bool = False
    has_admin_capability: bool = False
    is_system_app: bool = False
    uid: str = ""
    data_dir: str = ""
    apk_path: str = ""
    raw_dump: str = ""

    def to_dict(self):
        return asdict(self)

    def to_feature_vector(self) -> list:
        """Returns numeric feature vector for ML model."""
        return [
            self.dangerous_perm_count,
            int(self.has_boot_persistence),
            int(self.has_background_service),
            int(self.has_network_access),
            int(self.has_sms_access),
            int(self.has_mic_access),
            int(self.has_camera_access),
            int(self.has_location_access),
            int(self.has_install_capability),
            int(self.has_admin_capability),
            len(self.services),
            len(self.receivers),
        ]


class AppAnalyzer:
    """
    Analyzes installed Android apps using pm and dumpsys commands.
    Designed to run inside Termux.
    """

    def __init__(self):
        self._package_cache: dict[str, AppProfile] = {}

    def _run(self, cmd: str, timeout: int = 10) -> str:
        """Execute a shell command and return stdout."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""

    def get_installed_packages(self, include_system: bool = False) -> list[str]:
        """Return list of installed package names."""
        flag = "" if include_system else "-3"
        output = self._run(f"pm list packages {flag}")
        packages = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line[8:].strip())
        return sorted(packages)

    def analyze_package(self, package_name: str, force: bool = False) -> AppProfile:
        """Analyze a single package and return its AppProfile."""
        if not force and package_name in self._package_cache:
            return self._package_cache[package_name]

        profile = AppProfile(package_name=package_name)
        dump = self._run(f"dumpsys package {package_name}", timeout=15)
        profile.raw_dump = dump

        if dump:
            self._parse_dump(profile, dump)

        self._package_cache[package_name] = profile
        return profile

    def _parse_dump(self, profile: AppProfile, dump: str):
        """Parse dumpsys package output into AppProfile fields."""
        lines = dump.splitlines()

        # Version info
        m = re.search(r"versionName=(\S+)", dump)
        if m:
            profile.version_name = m.group(1)

        m = re.search(r"versionCode=(\d+)", dump)
        if m:
            profile.version_code = m.group(1)

        m = re.search(r"targetSdk=(\d+)", dump)
        if m:
            profile.target_sdk = int(m.group(1))

        m = re.search(r"minSdk=(\d+)", dump)
        if m:
            profile.min_sdk = int(m.group(1))

        # Install timestamps
        m = re.search(r"firstInstallTime=(.+)", dump)
        if m:
            profile.first_install = m.group(1).strip()

        m = re.search(r"lastUpdateTime=(.+)", dump)
        if m:
            profile.last_update = m.group(1).strip()

        # UID and paths
        m = re.search(r"userId=(\d+)", dump)
        if m:
            profile.uid = m.group(1)

        m = re.search(r"dataDir=(\S+)", dump)
        if m:
            profile.data_dir = m.group(1)

        m = re.search(r"codePath=(\S+)", dump)
        if m:
            profile.apk_path = m.group(1)

        # System app detection
        if "flags=[ SYSTEM" in dump or "FLAG_SYSTEM" in dump:
            profile.is_system_app = True

        # Parse permissions
        self._parse_permissions(profile, dump)

        # Parse components
        self._parse_components(profile, dump)

        # Derive capability flags
        self._derive_flags(profile)

    def _parse_permissions(self, profile: AppProfile, dump: str):
        """Extract permissions from dump."""
        perms = set()
        in_perms = False

        for line in dump.splitlines():
            if "requested permissions:" in line.lower():
                in_perms = True
                continue
            if "install permissions:" in line.lower() or "runtime permissions:" in line.lower():
                in_perms = True
                continue
            if in_perms:
                stripped = line.strip()
                if stripped.startswith("android.permission.") or \
                   stripped.startswith("com.android.") or \
                   "permission" in stripped.lower():
                    perm = stripped.split(":")[0].strip()
                    if perm:
                        perms.add(perm)
                elif stripped and not stripped.startswith(" ") and ":" not in stripped:
                    in_perms = False

        # Also scan raw for permission strings
        for m in re.finditer(r"(android\.permission\.\w+)", dump):
            perms.add(m.group(1))

        profile.permissions = list(perms)
        profile.dangerous_permissions = [p for p in perms if p in DANGEROUS_PERMISSIONS]
        profile.dangerous_perm_count = len(profile.dangerous_permissions)

    def _parse_components(self, profile: AppProfile, dump: str):
        """Extract services, receivers, activities from dump."""
        services = []
        receivers = []
        activities = []
        providers = []

        # Services
        for m in re.finditer(r"Service\{[^}]*\s+([\w.]+)\}", dump):
            services.append(m.group(1))
        # Also match declared services
        for m in re.finditer(r"android\.app\.Service.*?(\b[\w.]+Service\b)", dump):
            services.append(m.group(1))

        # Receivers
        for m in re.finditer(r"Receiver\{[^}]*\s+([\w.]+)\}", dump):
            receivers.append(m.group(1))

        # Activities
        for m in re.finditer(r"Activity\{[^}]*\s+([\w.]+)\}", dump):
            activities.append(m.group(1))

        # Providers
        for m in re.finditer(r"Provider\{[^}]*\s+([\w.]+)\}", dump):
            providers.append(m.group(1))

        profile.services = list(set(services))
        profile.receivers = list(set(receivers))
        profile.activities = list(set(activities))
        profile.providers = list(set(providers))

    def _derive_flags(self, profile: AppProfile):
        """Derive boolean capability flags from permissions and components."""
        perms = set(profile.permissions) | set(profile.dangerous_permissions)

        profile.has_boot_persistence = (
            "android.permission.RECEIVE_BOOT_COMPLETED" in perms or
            any("BOOT" in r.upper() for r in profile.receivers)
        )
        profile.has_background_service = (
            "android.permission.FOREGROUND_SERVICE" in perms or
            len(profile.services) > 0
        )
        profile.has_network_access = "android.permission.INTERNET" in perms
        profile.has_sms_access = any(p for p in perms if "SMS" in p)
        profile.has_mic_access = "android.permission.RECORD_AUDIO" in perms
        profile.has_camera_access = "android.permission.CAMERA" in perms
        profile.has_location_access = any(p for p in perms if "LOCATION" in p)
        profile.has_contact_access = any(p for p in perms if "CONTACTS" in p)
        profile.has_install_capability = "android.permission.REQUEST_INSTALL_PACKAGES" in perms
        profile.has_admin_capability = "android.permission.BIND_DEVICE_ADMIN" in perms

    def analyze_all(self, include_system: bool = False,
                    max_apps: Optional[int] = None) -> list[AppProfile]:
        """Analyze all installed packages."""
        packages = self.get_installed_packages(include_system)
        if max_apps:
            packages = packages[:max_apps]
        profiles = []
        for pkg in packages:
            profiles.append(self.analyze_package(pkg))
        return profiles

    def export_json(self, profiles: list[AppProfile], path: str):
        """Export profiles to JSON file."""
        data = [p.to_dict() for p in profiles]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)