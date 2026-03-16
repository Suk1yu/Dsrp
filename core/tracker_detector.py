"""
core/tracker_detector.py
Detects analytics SDKs and trackers embedded in Android apps
by scanning package names and APK contents against a signature database.
"""

import json
import re
import subprocess
from pathlib import Path
from dataclasses import dataclass, field


BUILTIN_TRACKERS = {
    "Facebook Analytics": {
        "packages": ["com.facebook.analytics", "com.facebook.appevents",
                     "com.facebook.FacebookSdk"],
        "domains": ["graph.facebook.com", "connect.facebook.net"],
        "description": "Facebook in-app analytics and events SDK",
    },
    "Firebase Analytics": {
        "packages": ["com.google.firebase.analytics", "com.google.firebase"],
        "domains": ["firebaselogging.googleapis.com", "firebase.google.com"],
        "description": "Google Firebase analytics",
    },
    "Google Analytics": {
        "packages": ["com.google.android.gms.analytics", "com.google.analytics"],
        "domains": ["www.google-analytics.com", "ssl.google-analytics.com"],
        "description": "Google Analytics / GA4",
    },
    "Adjust": {
        "packages": ["com.adjust.sdk"],
        "domains": ["app.adjust.com", "s2s.adjust.com"],
        "description": "Adjust mobile attribution and analytics",
    },
    "AppsFlyer": {
        "packages": ["com.appsflyer"],
        "domains": ["t.appsflyer.com", "impression.appsflyer.com"],
        "description": "AppsFlyer mobile attribution",
    },
    "Branch": {
        "packages": ["io.branch.referral"],
        "domains": ["api.branch.io", "bnc.lt"],
        "description": "Branch deep linking and attribution",
    },
    "Mixpanel": {
        "packages": ["com.mixpanel.android"],
        "domains": ["api.mixpanel.com", "decide.mixpanel.com"],
        "description": "Mixpanel product analytics",
    },
    "Amplitude": {
        "packages": ["com.amplitude.android"],
        "domains": ["api.amplitude.com", "api2.amplitude.com"],
        "description": "Amplitude product analytics",
    },
    "Flurry": {
        "packages": ["com.flurry.android"],
        "domains": ["data.flurry.com", "analytics.yahoo.com"],
        "description": "Flurry/Yahoo analytics",
    },
    "Crashlytics": {
        "packages": ["com.crashlytics.android", "com.google.firebase.crashlytics"],
        "domains": ["reports.crashlytics.com"],
        "description": "Firebase Crashlytics crash reporting",
    },
    "OneSignal": {
        "packages": ["com.onesignal"],
        "domains": ["api.onesignal.com", "onesignal.com"],
        "description": "OneSignal push notification and analytics",
    },
    "AppLovin": {
        "packages": ["com.applovin"],
        "domains": ["rt.applovin.com", "a.applovin.com"],
        "description": "AppLovin ad analytics",
    },
    "ironSource": {
        "packages": ["com.ironsource.mediationsdk"],
        "domains": ["outcome-ssp.supersonic.com"],
        "description": "ironSource mediation/analytics",
    },
    "Singular": {
        "packages": ["com.singular.sdk"],
        "domains": ["sdk-api.singular.net"],
        "description": "Singular mobile attribution",
    },
    "Kochava": {
        "packages": ["com.kochava.base"],
        "domains": ["control.kochava.com"],
        "description": "Kochava mobile measurement",
    },
}


@dataclass
class TrackerDetectionResult:
    package_name: str
    detected_trackers: list = field(default_factory=list)
    tracker_count: int = 0
    privacy_score: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    details: dict = field(default_factory=dict)


class TrackerDetector:
    """
    Detects tracker/analytics SDKs in installed Android applications.
    Uses package dump scanning and APK string extraction.
    """

    def __init__(self, db_path: str = None):
        self.tracker_db = dict(BUILTIN_TRACKERS)
        if db_path:
            self._load_custom_db(db_path)

    def _load_custom_db(self, path: str):
        try:
            with open(path) as f:
                custom = json.load(f)
                self.tracker_db.update(custom)
        except Exception:
            pass

    def _run(self, cmd: str) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=10)
            return r.stdout
        except Exception:
            return ""

    def detect_from_profile(self, profile) -> TrackerDetectionResult:
        """Detect trackers from an AppProfile using package dump data."""
        result = TrackerDetectionResult(package_name=profile.package_name)
        raw_text = profile.raw_dump.lower()

        for tracker_name, sig in self.tracker_db.items():
            matched = False
            match_reason = []

            for pkg in sig.get("packages", []):
                if pkg.lower() in raw_text:
                    matched = True
                    match_reason.append(f"package: {pkg}")

            for domain in sig.get("domains", []):
                if domain.lower() in raw_text:
                    matched = True
                    match_reason.append(f"domain: {domain}")

            if matched:
                result.detected_trackers.append(tracker_name)
                result.details[tracker_name] = {
                    "description": sig.get("description", ""),
                    "match_reasons": match_reason,
                }

        result.tracker_count = len(result.detected_trackers)
        result.privacy_score = self._score(result.tracker_count)
        return result

    def detect_from_apk(self, apk_path: str, package_name: str = "unknown") -> TrackerDetectionResult:
        """Detect trackers by extracting strings from an APK file."""
        result = TrackerDetectionResult(package_name=package_name)

        # Extract strings using unzip + strings (available in Termux)
        strings_out = self._run(
            f"unzip -p '{apk_path}' classes.dex 2>/dev/null | strings 2>/dev/null | head -5000"
        )
        if not strings_out:
            strings_out = self._run(f"strings '{apk_path}' 2>/dev/null | head -5000")

        text = strings_out.lower()

        for tracker_name, sig in self.tracker_db.items():
            matched = False
            match_reason = []

            for pkg in sig.get("packages", []):
                pattern = pkg.lower().replace(".", "[/\\.]")
                if re.search(pattern, text):
                    matched = True
                    match_reason.append(f"class: {pkg}")

            for domain in sig.get("domains", []):
                if domain.lower() in text:
                    matched = True
                    match_reason.append(f"domain: {domain}")

            if matched:
                result.detected_trackers.append(tracker_name)
                result.details[tracker_name] = {
                    "description": sig.get("description", ""),
                    "match_reasons": match_reason,
                }

        result.tracker_count = len(result.detected_trackers)
        result.privacy_score = self._score(result.tracker_count)
        return result

    def _score(self, count: int) -> str:
        if count >= 5:
            return "CRITICAL"
        elif count >= 3:
            return "HIGH"
        elif count >= 1:
            return "MEDIUM"
        return "LOW"

    def batch_detect(self, profiles: list) -> list[TrackerDetectionResult]:
        return [self.detect_from_profile(p) for p in profiles]

    def get_all_tracker_names(self) -> list[str]:
        return list(self.tracker_db.keys())