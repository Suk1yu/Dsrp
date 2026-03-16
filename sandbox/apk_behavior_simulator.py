"""
sandbox/apk_behavior_simulator.py
Simulates risk scoring for APK behavior based on static analysis.
Lightweight — no actual execution sandbox needed.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sandbox.apk_static_analyzer import APKAnalysisResult


@dataclass
class BehaviorSimReport:
    package_name: str
    simulated_behaviors: list = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"
    mitre_techniques: list = field(default_factory=list)


# Maps dangerous APIs -> simulated behavior descriptions
API_BEHAVIOR_MAP = {
    "Runtime command execution": {
        "behavior": "Executes arbitrary shell commands — command injection risk",
        "mitre": "T1059 - Command and Scripting Interpreter",
    },
    "Dynamic code loading (dropper indicator)": {
        "behavior": "Loads code from disk at runtime — dropper/downloader behavior",
        "mitre": "T1059.007 - Dynamic Code Loading",
    },
    "Audio/video recording": {
        "behavior": "Records audio or video — potential covert surveillance",
        "mitre": "T1123 - Audio Capture",
    },
    "SMS sending": {
        "behavior": "Sends SMS messages programmatically — premium SMS fraud risk",
        "mitre": "T1582 - SMS Control",
    },
    "Device admin usage": {
        "behavior": "Requests device administrator privileges — ransomware/spyware indicator",
        "mitre": "T1548 - Abuse Elevation Control Mechanism",
    },
    "APK installation capability": {
        "behavior": "Can install other APKs — second-stage dropper behavior",
        "mitre": "T1447 - Delete Device Data",
    },
    "Native code loading": {
        "behavior": "Loads native library — possible anti-analysis / rooting tool",
        "mitre": "T1625 - Hijack Execution Flow",
    },
    "Reflection (code obfuscation indicator)": {
        "behavior": "Uses reflection to hide API calls — obfuscation / evasion",
        "mitre": "T1406 - Obfuscated Files or Information",
    },
    "Root command execution": {
        "behavior": "Attempts root command execution — privilege escalation",
        "mitre": "T1626 - Abuse Elevation Control Mechanism",
    },
}


PERMISSION_BEHAVIOR_MAP = {
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "behavior": "Launches at device boot — persistence mechanism",
        "mitre": "T1398 - Boot or Logon Initialization Scripts",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "behavior": "Can install additional packages — dropper capability",
        "mitre": "T1476 - Deliver Malicious App via Authorized App Store",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "behavior": "Device administrator — can lock/wipe device",
        "mitre": "T1629 - Impair Defenses",
    },
    "android.permission.READ_SMS": {
        "behavior": "Reads all incoming SMS including OTPs — MFA bypass risk",
        "mitre": "T1412 - Capture SMS Messages",
    },
    "android.permission.RECORD_AUDIO": {
        "behavior": "Can activate microphone at any time",
        "mitre": "T1123 - Audio Capture",
    },
    "android.permission.CAMERA": {
        "behavior": "Can access camera for covert capture",
        "mitre": "T1512 - Video Capture",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "behavior": "Tracks location continuously in background",
        "mitre": "T1430 - Location Tracking",
    },
}


class APKBehaviorSimulator:
    """
    Produces a risk-scored behavioral simulation report from APK static analysis.
    Maps detected APIs and permissions to MITRE ATT&CK for Mobile techniques.
    """

    def simulate(self, static_result: "APKAnalysisResult") -> BehaviorSimReport:
        report = BehaviorSimReport(package_name=static_result.package_name)

        seen_behaviors = set()
        seen_mitre = set()

        # Map dangerous APIs to behaviors
        for api_desc in static_result.dangerous_apis.values():
            if api_desc in API_BEHAVIOR_MAP:
                entry = API_BEHAVIOR_MAP[api_desc]
                behavior = entry["behavior"]
                mitre = entry["mitre"]
                if behavior not in seen_behaviors:
                    report.simulated_behaviors.append(behavior)
                    seen_behaviors.add(behavior)
                    report.risk_score += 5
                if mitre not in seen_mitre:
                    report.mitre_techniques.append(mitre)
                    seen_mitre.add(mitre)

        # Map permissions to behaviors
        for perm in static_result.dangerous_permissions:
            if perm in PERMISSION_BEHAVIOR_MAP:
                entry = PERMISSION_BEHAVIOR_MAP[perm]
                behavior = entry["behavior"]
                mitre = entry["mitre"]
                if behavior not in seen_behaviors:
                    report.simulated_behaviors.append(behavior)
                    seen_behaviors.add(behavior)
                    report.risk_score += 3
                if mitre not in seen_mitre:
                    report.mitre_techniques.append(mitre)
                    seen_mitre.add(mitre)

        # Tracker count adds score
        report.risk_score += len(static_result.trackers_found) * 2

        # Suspicious strings
        report.risk_score += len(static_result.suspicious_strings) * 4

        # Multi-DEX
        if static_result.embedded_dex_count > 1:
            behavior = f"Multi-DEX APK ({static_result.embedded_dex_count} DEX files) — obfuscation/evasion"
            report.simulated_behaviors.append(behavior)
            report.risk_score += 5

        # Level
        if report.risk_score >= 40:
            report.risk_level = "CRITICAL"
        elif report.risk_score >= 20:
            report.risk_level = "HIGH"
        elif report.risk_score >= 8:
            report.risk_level = "MEDIUM"
        else:
            report.risk_level = "LOW"

        return report