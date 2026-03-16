"""
sandbox/apk_static_analyzer.py
Lightweight static analysis of APK files.
Extracts permissions, suspicious strings, embedded trackers, dangerous API usage.
"""

import re
import zipfile
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box


DANGEROUS_API_PATTERNS = {
    "Ljavax/crypto/Cipher;": "Cryptography usage (possible encryption/obfuscation)",
    "Ljava/lang/Runtime;->exec": "Runtime command execution",
    "Ljava/lang/ProcessBuilder": "Process spawning",
    "Landroid/telephony/SmsManager;->sendTextMessage": "SMS sending",
    "Landroid/media/MediaRecorder": "Audio/video recording",
    "Ljavax/net/ssl/SSLSocket": "Direct SSL socket (possible certificate pinning bypass)",
    "Ljava/lang/reflect/Method;->invoke": "Reflection (code obfuscation indicator)",
    "Ldalvik/system/DexClassLoader": "Dynamic code loading (dropper indicator)",
    "Ldalvik/system/PathClassLoader": "Class loading at runtime",
    "Landroid/content/pm/PackageInstaller": "APK installation capability",
    "Landroid/app/admin/DevicePolicyManager": "Device admin usage",
    "Landroid/provider/Telephony": "SMS/call log access",
    "Landroid/location/LocationManager": "Location access",
    "Landroid/hardware/Camera": "Camera access",
    "Ljavax/crypto/spec/SecretKeySpec": "Secret key crypto",
    "Base64": "Base64 encoding (possible payload hiding)",
    "exec(": "Shell command execution",
    "getRuntime": "Runtime access",
    "loadLibrary": "Native library loading",
    "System.loadLibrary": "Native code loading",
    "URLClassLoader": "Dynamic URL class loading",
    "chmod 777": "World-writable permission setting",
    "su ": "Root command execution",
    "/system/bin/su": "Direct su binary access",
}

TRACKER_STRING_PATTERNS = {
    "com.facebook": "Facebook SDK",
    "com.google.firebase": "Firebase",
    "com.google.analytics": "Google Analytics",
    "com.mixpanel": "Mixpanel",
    "com.amplitude": "Amplitude",
    "com.adjust": "Adjust",
    "com.appsflyer": "AppsFlyer",
    "io.branch": "Branch",
    "com.flurry": "Flurry",
    "com.crashlytics": "Crashlytics",
    "com.onesignal": "OneSignal",
    "com.segment": "Segment",
    "com.localytics": "Localytics",
    "com.swrve": "Swrve",
    "com.kochava": "Kochava",
}

SUSPICIOUS_STRINGS = [
    "keylogger", "screenshot", "intercept", "exfil",
    "hidden", "stealth", "invisible", "spy", "monitor",
    "admin", "root", "exploit", "payload", "backdoor",
    "c2", "command.*control", "botnet", "zombie",
    "hooking", "ptrace", "frida",
]


@dataclass
class APKAnalysisResult:
    apk_path: str
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    md5: str = ""
    sha256: str = ""
    file_size_kb: float = 0.0
    permissions: list = field(default_factory=list)
    dangerous_permissions: list = field(default_factory=list)
    activities: list = field(default_factory=list)
    services: list = field(default_factory=list)
    receivers: list = field(default_factory=list)
    providers: list = field(default_factory=list)
    dangerous_apis: dict = field(default_factory=dict)
    trackers_found: list = field(default_factory=list)
    suspicious_strings: list = field(default_factory=list)
    native_libs: list = field(default_factory=list)
    embedded_dex_count: int = 0
    risk_score: int = 0
    risk_level: str = "LOW"
    error: str = ""


class APKStaticAnalyzer:
    """
    Static analysis of APK files using Python zipfile (no root required).
    Extracts manifest, scans DEX bytecode for patterns.
    """

    def analyze(self, apk_path: str) -> APKAnalysisResult:
        result = APKAnalysisResult(apk_path=apk_path)

        if not os.path.exists(apk_path):
            result.error = f"File not found: {apk_path}"
            return result

        # File info
        result.file_size_kb = round(os.path.getsize(apk_path) / 1024, 1)
        result.md5, result.sha256 = self._hash_file(apk_path)

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                # Parse AndroidManifest.xml (binary XML — use string extraction)
                self._parse_manifest(apk, result)

                # Scan DEX files for patterns
                dex_files = [f for f in apk.namelist()
                             if f.endswith(".dex") or f.startswith("classes")]
                result.embedded_dex_count = len(dex_files)

                for dex_name in dex_files:
                    try:
                        dex_data = apk.read(dex_name).decode("latin-1", errors="replace")
                        self._scan_dex(dex_data, result)
                    except Exception:
                        pass

                # Native libraries
                result.native_libs = [
                    f for f in apk.namelist()
                    if f.endswith(".so")
                ]

        except zipfile.BadZipFile:
            result.error = "Not a valid APK/ZIP file"
            return result
        except Exception as e:
            result.error = str(e)

        result.risk_score, result.risk_level = self._calculate_risk(result)
        return result

    def _hash_file(self, path: str) -> tuple[str, str]:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()

    def _parse_manifest(self, apk: zipfile.ZipFile, result: APKAnalysisResult):
        """Extract info from binary AndroidManifest.xml via string scanning."""
        try:
            manifest_data = apk.read("AndroidManifest.xml").decode("latin-1", errors="replace")
        except Exception:
            return

        # Extract permission strings
        for m in re.finditer(r"android\.permission\.(\w+)", manifest_data):
            perm = f"android.permission.{m.group(1)}"
            if perm not in result.permissions:
                result.permissions.append(perm)

        # Extract package-like strings for component names
        for m in re.finditer(r"([\w]+\.[\w]+\.[\w.]+)", manifest_data):
            val = m.group(1)
            if "Activity" in val:
                result.activities.append(val)
            elif "Service" in val:
                result.services.append(val)
            elif "Receiver" in val:
                result.receivers.append(val)
            elif "Provider" in val:
                result.providers.append(val)

        # Package name from manifest
        m = re.search(r"package[\"=\s]+([\w.]+)", manifest_data)
        if m:
            result.package_name = m.group(1)

        # Filter dangerous permissions
        from core.app_analyzer import DANGEROUS_PERMISSIONS
        result.dangerous_permissions = [p for p in result.permissions
                                        if p in DANGEROUS_PERMISSIONS]

    def _scan_dex(self, dex_data: str, result: APKAnalysisResult):
        """Scan DEX bytecode for dangerous API patterns and tracker strings."""
        lower = dex_data.lower()

        # Dangerous APIs
        for pattern, description in DANGEROUS_API_PATTERNS.items():
            if pattern.lower() in lower:
                if description not in result.dangerous_apis.values():
                    result.dangerous_apis[pattern] = description

        # Tracker strings
        for pattern, name in TRACKER_STRING_PATTERNS.items():
            if pattern.lower() in lower and name not in result.trackers_found:
                result.trackers_found.append(name)

        # Suspicious strings
        for pattern in SUSPICIOUS_STRINGS:
            if re.search(pattern, lower) and pattern not in result.suspicious_strings:
                result.suspicious_strings.append(pattern)

    def _calculate_risk(self, result: APKAnalysisResult) -> tuple[int, str]:
        score = 0

        score += len(result.dangerous_permissions) * 3
        score += len(result.dangerous_apis) * 2
        score += len(result.trackers_found) * 1
        score += len(result.suspicious_strings) * 3
        score += len(result.native_libs) * 1

        if result.embedded_dex_count > 1:
            score += 5  # multi-dex often indicates obfuscation/evasion

        if any("BIND_DEVICE_ADMIN" in p for p in result.dangerous_permissions):
            score += 10
        if any("REQUEST_INSTALL_PACKAGES" in p for p in result.dangerous_permissions):
            score += 8

        if score >= 40:
            level = "CRITICAL"
        elif score >= 20:
            level = "HIGH"
        elif score >= 8:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level

    def print_report(self, result: APKAnalysisResult):
        console = Console()
        color = {"LOW": "green", "MEDIUM": "yellow",
                 "HIGH": "red", "CRITICAL": "bold red"}.get(result.risk_level, "white")

        console.print(Panel(
            f"[bold]Package:[/bold] {result.package_name}\n"
            f"[bold]File:[/bold] {result.apk_path} ({result.file_size_kb} KB)\n"
            f"[bold]MD5:[/bold] {result.md5}\n"
            f"[bold]SHA256:[/bold] {result.sha256}\n"
            f"[bold]Risk:[/bold] [{color}]{result.risk_level}[/{color}] (score: {result.risk_score})",
            title="APK Analysis Report", border_style=color
        ))

        if result.dangerous_permissions:
            console.print(f"\n[red]Dangerous Permissions ({len(result.dangerous_permissions)}):[/red]")
            for p in result.dangerous_permissions:
                console.print(f"  • {p}")

        if result.dangerous_apis:
            console.print(f"\n[red]Dangerous API Usage ({len(result.dangerous_apis)}):[/red]")
            for api, desc in list(result.dangerous_apis.items())[:10]:
                console.print(f"  • {desc}")

        if result.trackers_found:
            console.print(f"\n[yellow]Embedded Trackers ({len(result.trackers_found)}):[/yellow]")
            for t in result.trackers_found:
                console.print(f"  • {t}")

        if result.suspicious_strings:
            console.print(f"\n[red]Suspicious Strings ({len(result.suspicious_strings)}):[/red]")
            for s in result.suspicious_strings:
                console.print(f"  • {s}")

        if result.native_libs:
            console.print(f"\n[dim]Native Libraries ({len(result.native_libs)}):[/dim]")
            for lib in result.native_libs[:5]:
                console.print(f"  • {lib}")