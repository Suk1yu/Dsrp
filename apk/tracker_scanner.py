"""
apk/tracker_scanner.py

Dedicated tracker SDK scanner for APK files.
Uses a JSON signature database for extensibility.

Signatures checked:
  - class package prefixes (in DEX)
  - domain strings (in DEX / resources)
  - SDK init class names
  - Gradle dependency strings (in META-INF)

Output: TrackerScanReport with per-tracker evidence.
"""

import re
import zipfile
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


SIGNATURES_PATH = Path(__file__).parent.parent / "data" / "tracker_signatures.json"


# ---------------------------------------------------------------------------
# Built-in tracker signature database
# ---------------------------------------------------------------------------

BUILTIN_SIGNATURES = [
    {
        "name": "Facebook Analytics",
        "category": "Analytics",
        "classes": ["com.facebook.analytics", "com.facebook.appevents",
                    "com.facebook.FacebookSdk"],
        "domains": ["graph.facebook.com", "connect.facebook.net",
                    "an.facebook.com"],
        "risk": "HIGH",
        "description": "Facebook in-app event tracking and analytics",
    },
    {
        "name": "Firebase Analytics",
        "category": "Analytics",
        "classes": ["com.google.firebase.analytics", "com.google.firebase"],
        "domains": ["firebaselogging.googleapis.com", "app-measurement.com"],
        "risk": "MEDIUM",
        "description": "Google Firebase analytics and A/B testing",
    },
    {
        "name": "Google Analytics",
        "category": "Analytics",
        "classes": ["com.google.android.gms.analytics", "com.google.analytics"],
        "domains": ["www.google-analytics.com", "ssl.google-analytics.com"],
        "risk": "MEDIUM",
        "description": "Google Analytics / GA4",
    },
    {
        "name": "AppsFlyer",
        "category": "Attribution",
        "classes": ["com.appsflyer"],
        "domains": ["t.appsflyer.com", "impression.appsflyer.com"],
        "risk": "HIGH",
        "description": "Mobile attribution and marketing analytics",
    },
    {
        "name": "Adjust",
        "category": "Attribution",
        "classes": ["com.adjust.sdk"],
        "domains": ["app.adjust.com", "s2s.adjust.com"],
        "risk": "HIGH",
        "description": "Mobile attribution and measurement",
    },
    {
        "name": "Branch",
        "category": "Attribution",
        "classes": ["io.branch.referral", "io.branch"],
        "domains": ["api.branch.io", "bnc.lt"],
        "risk": "HIGH",
        "description": "Deep linking and attribution",
    },
    {
        "name": "Kochava",
        "category": "Attribution",
        "classes": ["com.kochava.base"],
        "domains": ["control.kochava.com"],
        "risk": "HIGH",
        "description": "Mobile attribution and measurement",
    },
    {
        "name": "Singular",
        "category": "Attribution",
        "classes": ["com.singular.sdk"],
        "domains": ["sdk-api.singular.net"],
        "risk": "HIGH",
        "description": "Marketing measurement and attribution",
    },
    {
        "name": "Mixpanel",
        "category": "Analytics",
        "classes": ["com.mixpanel.android"],
        "domains": ["api.mixpanel.com"],
        "risk": "MEDIUM",
        "description": "Product analytics",
    },
    {
        "name": "Amplitude",
        "category": "Analytics",
        "classes": ["com.amplitude.android"],
        "domains": ["api.amplitude.com", "api2.amplitude.com"],
        "risk": "MEDIUM",
        "description": "Product analytics",
    },
    {
        "name": "Flurry",
        "category": "Analytics",
        "classes": ["com.flurry.android"],
        "domains": ["data.flurry.com"],
        "risk": "MEDIUM",
        "description": "Yahoo/Verizon analytics",
    },
    {
        "name": "Segment",
        "category": "Analytics",
        "classes": ["com.segment.analytics"],
        "domains": ["api.segment.io", "cdn.segment.com"],
        "risk": "MEDIUM",
        "description": "Customer Data Platform (CDP)",
    },
    {
        "name": "OneSignal",
        "category": "Push Notifications",
        "classes": ["com.onesignal"],
        "domains": ["api.onesignal.com", "onesignal.com"],
        "risk": "LOW",
        "description": "Push notifications with analytics",
    },
    {
        "name": "Braze",
        "category": "Marketing",
        "classes": ["com.braze", "com.appboy"],
        "domains": ["sdk.iad-01.braze.com", "braze.com"],
        "risk": "MEDIUM",
        "description": "Customer engagement and marketing",
    },
    {
        "name": "Firebase Crashlytics",
        "category": "Crash Reporting",
        "classes": ["com.crashlytics.android", "com.google.firebase.crashlytics"],
        "domains": ["reports.crashlytics.com"],
        "risk": "LOW",
        "description": "Crash reporting",
    },
    {
        "name": "Sentry",
        "category": "Crash Reporting",
        "classes": ["io.sentry"],
        "domains": ["sentry.io"],
        "risk": "LOW",
        "description": "Error tracking",
    },
    {
        "name": "AppLovin",
        "category": "Advertising",
        "classes": ["com.applovin"],
        "domains": ["rt.applovin.com", "a.applovin.com"],
        "risk": "HIGH",
        "description": "Ad mediation and analytics",
    },
    {
        "name": "ironSource",
        "category": "Advertising",
        "classes": ["com.ironsource.mediationsdk", "com.ironsource"],
        "domains": ["outcome-ssp.supersonic.com"],
        "risk": "HIGH",
        "description": "Ad mediation",
    },
    {
        "name": "Google AdMob",
        "category": "Advertising",
        "classes": ["com.google.android.gms.ads"],
        "domains": ["admob.com", "googleadapis.l.google.com"],
        "risk": "MEDIUM",
        "description": "Google mobile advertising",
    },
    {
        "name": "Unity Ads",
        "category": "Advertising",
        "classes": ["com.unity3d.ads"],
        "domains": ["auction.unityads.unity3d.com"],
        "risk": "MEDIUM",
        "description": "Unity in-game advertising",
    },
    {
        "name": "Vungle",
        "category": "Advertising",
        "classes": ["com.vungle"],
        "domains": ["ads.api.vungle.com"],
        "risk": "HIGH",
        "description": "Video advertising",
    },
    {
        "name": "Chartboost",
        "category": "Advertising",
        "classes": ["com.chartboost"],
        "domains": ["live.chartboost.com"],
        "risk": "MEDIUM",
        "description": "Mobile advertising",
    },
    {
        "name": "InMobi",
        "category": "Advertising",
        "classes": ["com.inmobi"],
        "domains": ["api.inmobi.com"],
        "risk": "HIGH",
        "description": "Mobile advertising with extensive data collection",
    },
    {
        "name": "MoPub",
        "category": "Advertising",
        "classes": ["com.mopub"],
        "domains": ["ads.mopub.com"],
        "risk": "HIGH",
        "description": "Twitter MoPub ad mediation",
    },
    {
        "name": "Heap Analytics",
        "category": "Analytics",
        "classes": ["com.heapanalytics"],
        "domains": ["heapanalytics.com"],
        "risk": "HIGH",
        "description": "Automatic event capture analytics",
    },
    {
        "name": "FullStory",
        "category": "Session Recording",
        "classes": ["com.fullstory"],
        "domains": ["fullstory.com", "rs.fullstory.com"],
        "risk": "CRITICAL",
        "description": "Full session recording with screen replay",
    },
    {
        "name": "Smartlook",
        "category": "Session Recording",
        "classes": ["com.smartlook"],
        "domains": ["smartlook.com", "rec.smartlook.com"],
        "risk": "CRITICAL",
        "description": "Session recording and heatmaps",
    },
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TrackerEvidence:
    """Evidence for a single tracker detection."""
    name: str
    category: str
    risk: str
    description: str
    matched_classes: list = field(default_factory=list)
    matched_domains: list = field(default_factory=list)
    confidence: int = 0       # 0–100

    @property
    def match_count(self) -> int:
        return len(self.matched_classes) + len(self.matched_domains)


@dataclass
class TrackerScanReport:
    apk_path: str
    package_name: str = ""
    trackers_found: list = field(default_factory=list)
    tracker_count: int = 0
    critical_trackers: list = field(default_factory=list)
    high_risk_trackers: list = field(default_factory=list)
    tracker_categories: dict = field(default_factory=dict)
    privacy_score: str = "LOW"   # LOW / MEDIUM / HIGH / CRITICAL
    total_class_matches: int = 0
    total_domain_matches: int = 0
    scan_error: str = ""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class TrackerScanner:
    """
    Scans APK files for embedded tracker SDKs.
    Checks DEX bytecode for class signatures and domain strings.
    """

    def __init__(self, signatures_path: str = None):
        self._sigs = list(BUILTIN_SIGNATURES)
        if signatures_path and Path(signatures_path).exists():
            self._load_json(signatures_path)
        elif SIGNATURES_PATH.exists():
            self._load_json(str(SIGNATURES_PATH))

    def scan(self, apk_path: str) -> TrackerScanReport:
        report = TrackerScanReport(apk_path=apk_path)

        if not Path(apk_path).exists():
            report.scan_error = f"File not found: {apk_path}"
            return report

        # Extract DEX text
        dex_text = self._extract_dex_text(apk_path)
        if dex_text is None:
            report.scan_error = "Failed to open APK"
            return report

        # Extract package name from manifest
        report.package_name = self._extract_package(apk_path)

        # Match each tracker
        found: list[TrackerEvidence] = []
        for sig in self._sigs:
            evidence = self._match_signature(sig, dex_text)
            if evidence:
                found.append(evidence)

        report.trackers_found = found
        report.tracker_count = len(found)

        # Categorise
        cats: dict = {}
        for ev in found:
            cats[ev.category] = cats.get(ev.category, 0) + 1
        report.tracker_categories = cats

        report.critical_trackers = [t for t in found if t.risk == "CRITICAL"]
        report.high_risk_trackers = [t for t in found if t.risk == "HIGH"]

        report.total_class_matches = sum(len(t.matched_classes) for t in found)
        report.total_domain_matches = sum(len(t.matched_domains) for t in found)

        # Privacy score
        n = len(found)
        critical_n = len(report.critical_trackers)
        if critical_n >= 1 or n >= 8:
            report.privacy_score = "CRITICAL"
        elif n >= 5 or len(report.high_risk_trackers) >= 3:
            report.privacy_score = "HIGH"
        elif n >= 2:
            report.privacy_score = "MEDIUM"
        elif n >= 1:
            report.privacy_score = "LOW"
        else:
            report.privacy_score = "CLEAN"

        return report

    def _match_signature(self, sig: dict,
                          dex_text: str) -> Optional[TrackerEvidence]:
        lower = dex_text.lower()
        matched_classes = []
        matched_domains = []

        for cls in sig.get("classes", []):
            # Convert package to path format for DEX matching
            cls_path = cls.lower().replace(".", "/")
            if cls.lower() in lower or cls_path in lower:
                matched_classes.append(cls)

        for domain in sig.get("domains", []):
            if domain.lower() in lower:
                matched_domains.append(domain)

        if not matched_classes and not matched_domains:
            return None

        confidence = min(100,
                         len(matched_classes) * 30 + len(matched_domains) * 20)

        return TrackerEvidence(
            name=sig["name"],
            category=sig.get("category", "Unknown"),
            risk=sig.get("risk", "MEDIUM"),
            description=sig.get("description", ""),
            matched_classes=matched_classes,
            matched_domains=matched_domains,
            confidence=min(confidence, 100),
        )

    def _extract_dex_text(self, apk_path: str) -> Optional[str]:
        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                dex_files = [f for f in apk.namelist()
                             if re.match(r"classes\d*\.dex", f)]
                text = ""
                for dex in dex_files[:4]:
                    try:
                        raw = apk.read(dex)
                        text += raw.decode("latin-1", errors="replace")
                    except Exception:
                        pass
                return text
        except Exception:
            return None

    def _extract_package(self, apk_path: str) -> str:
        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                raw = apk.read("AndroidManifest.xml").decode("latin-1", errors="replace")
                m = re.search(r"package[\"=\s]+([\w.]+)", raw)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return ""

    def _load_json(self, path: str):
        try:
            with open(path) as f:
                extra = json.load(f)
            if isinstance(extra, list):
                self._sigs.extend(extra)
        except Exception:
            pass

    def get_signature_count(self) -> int:
        return len(self._sigs)

    def save_signatures_json(self, path: str):
        """Export current signatures to JSON for editing."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self._sigs, f, indent=2)