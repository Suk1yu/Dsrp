"""
core/behavior_engine.py
Detects suspicious behavioral patterns from app profiles.
Flags dangerous permission combinations.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.app_analyzer import AppProfile


# (label, description, weight)
BEHAVIOR_RULES = [
    {
        "id": "SMS_EXFIL",
        "label": "SMS Exfiltration",
        "description": "App reads/sends SMS AND has internet access — possible SMS exfiltration.",
        "weight": 9,
        "check": lambda p: p.has_sms_access and p.has_network_access,
    },
    {
        "id": "MIC_EXFIL",
        "label": "Audio Surveillance",
        "description": "App records audio AND has internet access — possible covert recording.",
        "weight": 9,
        "check": lambda p: p.has_mic_access and p.has_network_access,
    },
    {
        "id": "CAM_EXFIL",
        "label": "Camera Surveillance",
        "description": "App uses camera AND has internet access — possible unauthorized capture.",
        "weight": 8,
        "check": lambda p: p.has_camera_access and p.has_network_access,
    },
    {
        "id": "BOOT_NET",
        "label": "Boot Persistence + Network",
        "description": "App starts at boot AND has network access — persistent background agent.",
        "weight": 7,
        "check": lambda p: p.has_boot_persistence and p.has_network_access,
    },
    {
        "id": "BOOT_SVC",
        "label": "Boot Persistence + Background Service",
        "description": "App starts at boot AND runs background services — possible stalkerware.",
        "weight": 7,
        "check": lambda p: p.has_boot_persistence and p.has_background_service,
    },
    {
        "id": "BG_NET_SVC",
        "label": "Background Service + Network",
        "description": "App runs background services AND has network access — hidden activity possible.",
        "weight": 5,
        "check": lambda p: p.has_background_service and p.has_network_access,
    },
    {
        "id": "LOC_EXFIL",
        "label": "Location Tracking",
        "description": "App accesses location AND has internet access — potential tracking.",
        "weight": 7,
        "check": lambda p: p.has_location_access and p.has_network_access,
    },
    {
        "id": "CONTACT_EXFIL",
        "label": "Contact Exfiltration",
        "description": "App reads contacts AND has internet — potential data harvesting.",
        "weight": 7,
        "check": lambda p: p.has_contact_access and p.has_network_access,
    },
    {
        "id": "APK_INSTALL",
        "label": "APK Install Capability",
        "description": "App can install other APKs — dropper or adware behavior.",
        "weight": 8,
        "check": lambda p: p.has_install_capability,
    },
    {
        "id": "DEVICE_ADMIN",
        "label": "Device Admin Privilege",
        "description": "App requests device admin rights — often used by spyware.",
        "weight": 10,
        "check": lambda p: p.has_admin_capability,
    },
    {
        "id": "HIGH_PERM_COUNT",
        "label": "Excessive Dangerous Permissions",
        "description": "App requests a large number of dangerous permissions.",
        "weight": 5,
        "check": lambda p: p.dangerous_perm_count >= 8,
    },
    {
        "id": "FULL_SURVEILLANCE",
        "label": "Full Surveillance Package",
        "description": "App has SMS + MIC + CAM + LOCATION + INTERNET — comprehensive spyware indicators.",
        "weight": 10,
        "check": lambda p: all([p.has_sms_access, p.has_mic_access,
                                p.has_camera_access, p.has_location_access,
                                p.has_network_access]),
    },
]

RISK_THRESHOLDS = {
    "CRITICAL": 18,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 0,
}


@dataclass
class BehaviorReport:
    package_name: str
    score: int = 0
    level: str = "LOW"
    flags: list = field(default_factory=list)
    triggered_rules: list = field(default_factory=list)
    details: list = field(default_factory=list)


class BehaviorEngine:
    """
    Applies rule-based behavioral analysis to AppProfile objects.
    Returns a risk score and list of triggered behavioral flags.
    """

    def evaluate(self, profile: "AppProfile") -> dict:
        """Evaluate an AppProfile and return risk dict."""
        report = self._run_rules(profile)
        return {
            "package_name": report.package_name,
            "score": report.score,
            "level": report.level,
            "flags": report.flags,
            "triggered_rules": report.triggered_rules,
            "details": report.details,
        }

    def evaluate_full(self, profile: "AppProfile") -> BehaviorReport:
        return self._run_rules(profile)

    def _run_rules(self, profile: "AppProfile") -> BehaviorReport:
        report = BehaviorReport(package_name=profile.package_name)

        for rule in BEHAVIOR_RULES:
            try:
                if rule["check"](profile):
                    report.score += rule["weight"]
                    report.flags.append(rule["label"])
                    report.triggered_rules.append(rule["id"])
                    report.details.append(rule["description"])
            except Exception:
                pass

        # Determine level
        for level, threshold in RISK_THRESHOLDS.items():
            if report.score >= threshold:
                report.level = level
                break

        return report

    def batch_evaluate(self, profiles: list) -> list[BehaviorReport]:
        return [self.evaluate_full(p) for p in profiles]