"""
network/tracker_detector.py

Domain-based tracker detection engine.
Loads tracker_domains.json and matches DNS queries / hostnames.

CPU cost: Near zero (dict lookup, O(1) per query)
"""

import json
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Built-in tracker DB (extended, categorised)
# ---------------------------------------------------------------------------

BUILTIN_TRACKER_DB: dict[str, str] = {
    # ── Advertising ──────────────────────────────────────────────────────
    "doubleclick.net":          "Google DoubleClick Ads",
    "googlesyndication.com":    "Google AdSense",
    "googleadservices.com":     "Google Ad Services",
    "googletagmanager.com":     "Google Tag Manager",
    "googletagservices.com":    "Google Tag Services",
    "adservice.google.com":     "Google Ad Service",
    "ads.twitter.com":          "Twitter Ads",
    "advertising.apple.com":    "Apple Advertising",
    "mopub.com":                "Twitter MoPub Ads",
    "inmobi.com":               "InMobi Ads",
    "admob.com":                "Google AdMob",
    "chartboost.com":           "Chartboost Ads",
    "ironsrc.com":              "ironSource Ads",
    "unity3d.com":              "Unity Ads",
    "applovin.com":             "AppLovin Ads",
    "moatads.com":              "Moat Ad Verification",
    "criteo.com":               "Criteo Retargeting",
    "taboola.com":              "Taboola Native Ads",
    "outbrain.com":             "Outbrain Ads",
    "rubiconproject.com":       "Rubicon Project Ads",
    "pubmatic.com":             "PubMatic Ad Exchange",
    "openx.net":                "OpenX Ad Exchange",
    "appnexus.com":             "AppNexus (Xandr) Ads",
    "adcolony.com":             "AdColony Video Ads",
    "vungle.com":               "Vungle Video Ads",
    "startappservice.com":      "StartApp Ads",
    "smartadserver.com":        "Smart Ad Server",

    # ── Analytics ────────────────────────────────────────────────────────
    "google-analytics.com":     "Google Analytics",
    "ssl.google-analytics.com": "Google Analytics (SSL)",
    "analytics.google.com":     "Google Analytics 4",
    "firebase.google.com":      "Firebase Analytics",
    "firebaselogging.googleapis.com": "Firebase Logging",
    "app-measurement.com":      "Firebase App Measurement",
    "connect.facebook.net":     "Facebook SDK",
    "graph.facebook.com":       "Facebook Graph API",
    "an.facebook.com":          "Facebook Audience Network",
    "analytics.facebook.com":   "Facebook Analytics",
    "api.mixpanel.com":         "Mixpanel Analytics",
    "decide.mixpanel.com":      "Mixpanel Decide",
    "api.amplitude.com":        "Amplitude Analytics",
    "api2.amplitude.com":       "Amplitude Analytics v2",
    "flurry.com":               "Yahoo Flurry Analytics",
    "data.flurry.com":          "Flurry Data",
    "heapanalytics.com":        "Heap Analytics",
    "fullstory.com":            "FullStory Session Recording",
    "logrocket.com":            "LogRocket Session Recording",
    "hotjar.com":               "Hotjar Heatmaps",
    "mouseflow.com":            "Mouseflow Recording",
    "smartlook.com":            "Smartlook Recording",
    "intercom.io":              "Intercom Analytics",
    "segment.com":              "Segment CDP",
    "api.segment.io":           "Segment API",
    "cdn.segment.com":          "Segment CDN",
    "stats.pusher.com":         "Pusher Stats",
    "newrelic.com":             "New Relic APM",
    "datadoghq.com":            "Datadog APM",

    # ── Attribution / Mobile Measurement ─────────────────────────────────
    "t.appsflyer.com":          "AppsFlyer Attribution",
    "impression.appsflyer.com": "AppsFlyer Impression",
    "app.adjust.com":           "Adjust Attribution",
    "s2s.adjust.com":           "Adjust S2S",
    "adjust.com":               "Adjust SDK",
    "api.branch.io":            "Branch Attribution",
    "bnc.lt":                   "Branch Short Links",
    "app.link":                 "Branch App Links",
    "control.kochava.com":      "Kochava Attribution",
    "sdk-api.singular.net":     "Singular Attribution",
    "singular.net":             "Singular Attribution",
    "go.onelink.me":            "AppsFlyer OneLink",
    "skadnetwork.apple.com":    "Apple SKAdNetwork",

    # ── Push Notifications ────────────────────────────────────────────────
    "onesignal.com":            "OneSignal Push",
    "api.onesignal.com":        "OneSignal API",
    "push.onesignal.com":       "OneSignal Push",
    "urbanairship.com":         "Airship Push",
    "api.urbanairship.com":     "Airship API",
    "push.amazonaws.com":       "AWS SNS Push",
    "fcm.googleapis.com":       "Firebase Cloud Messaging",
    "mtalk.google.com":         "Google Push (FCM)",
    "braze.com":                "Braze Push",
    "customer.io":              "Customer.io Push",

    # ── Social / Identity ─────────────────────────────────────────────────
    "twitter.com":              "Twitter Social",
    "linkedin.com":             "LinkedIn Social",
    "platform.twitter.com":     "Twitter Platform",
    "assets.pinterest.com":     "Pinterest Ads",
    "snapkit.snapchat.com":     "Snapchat SDK",
    "sc-static.net":            "Snapchat Static",

    # ── Error / Crash Reporting ───────────────────────────────────────────
    "reports.crashlytics.com":  "Firebase Crashlytics",
    "settings.crashlytics.com": "Crashlytics Config",
    "sentry.io":                "Sentry Error Tracking",
    "bugsnag.com":              "Bugsnag Error Tracking",
    "rollbar.com":              "Rollbar Error Tracking",

    # ── Data Brokers ─────────────────────────────────────────────────────
    "scorecardresearch.com":    "Comscore/Scorecard Research",
    "quantserve.com":           "Quantcast",
    "bluekai.com":              "Oracle BlueKai DMP",
    "exelate.com":              "Nielsen ExelAte",
    "addthis.com":              "AddThis Sharing Tracker",
    "sharethis.com":            "ShareThis Tracker",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TrackerMatch:
    domain: str
    tracker_name: str
    category: str = ""
    confidence: int = 100
    matched_rule: str = ""   # exact / subdomain / pattern

    def to_row(self) -> list:
        return [self.domain[:40], self.tracker_name[:35],
                self.matched_rule, str(self.confidence) + "%"]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class TrackerDetector:
    """
    Fast domain-to-tracker mapping engine.
    
    Matching strategy (fastest first):
    1. Exact match         — O(1) dict lookup
    2. Subdomain match     — walk up parent domains
    3. Regex patterns      — for wildcard rules (least common)
    
    Database sources:
    - Built-in BUILTIN_TRACKER_DB
    - External JSON file (tracker_domains.json)
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db: dict[str, str] = dict(BUILTIN_TRACKER_DB)
        self._patterns: list[tuple[re.Pattern, str]] = []

        if db_path:
            self._load_json(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, domain: str) -> Optional[TrackerMatch]:
        """Check if a domain is a known tracker. Returns match or None."""
        if not domain:
            return None
        domain = domain.lower().strip(".")

        # 1. Exact
        if domain in self._db:
            return TrackerMatch(
                domain=domain,
                tracker_name=self._db[domain],
                matched_rule="exact",
            )

        # 2. Subdomain walk
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._db:
                return TrackerMatch(
                    domain=domain,
                    tracker_name=self._db[parent],
                    matched_rule=f"subdomain:{parent}",
                )

        # 3. Regex patterns
        for pattern, name in self._patterns:
            if pattern.search(domain):
                return TrackerMatch(
                    domain=domain,
                    tracker_name=name,
                    matched_rule="regex",
                    confidence=80,
                )

        return None

    def check_batch(self, domains: list[str]) -> list[Optional[TrackerMatch]]:
        return [self.check(d) for d in domains]

    def is_tracker(self, domain: str) -> bool:
        return self.check(domain) is not None

    def get_tracker_name(self, domain: str) -> str:
        match = self.check(domain)
        return match.tracker_name if match else ""

    def get_all_entries(self) -> dict[str, str]:
        return dict(self._db)

    def count(self) -> int:
        return len(self._db)

    def add(self, domain: str, tracker_name: str):
        self._db[domain.lower().strip(".")] = tracker_name

    def add_pattern(self, pattern: str, tracker_name: str):
        try:
            self._patterns.append((re.compile(pattern, re.IGNORECASE), tracker_name))
        except Exception:
            pass

    def build_flat_dict(self) -> dict[str, str]:
        """Return {domain: tracker_name} dict for injection into other modules."""
        return dict(self._db)

    # ------------------------------------------------------------------
    # JSON I/O
    # ------------------------------------------------------------------

    def _load_json(self, path: str):
        try:
            with open(path) as f:
                data = json.load(f)

            if isinstance(data, dict):
                # Format: {"domain": "tracker_name"}
                for k, v in data.items():
                    self._db[k.lower()] = str(v)

            elif isinstance(data, list):
                # Format: [{"domain": ..., "name": ...}]
                for entry in data:
                    if isinstance(entry, dict):
                        domain = entry.get("domain", "").lower()
                        name = entry.get("name", entry.get("tracker", "unknown"))
                        if domain:
                            self._db[domain] = name
                    elif isinstance(entry, str):
                        # Plain list of domains
                        self._db[entry.lower()] = "Tracker"
        except Exception:
            pass

    def save_json(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self._db, f, indent=2, sort_keys=True)

    def get_categories_summary(self) -> dict[str, int]:
        """Count trackers per rough category based on name keywords."""
        cats: dict[str, int] = {}
        for name in self._db.values():
            n_lower = name.lower()
            if any(w in n_lower for w in ["ad", "ads", "advert"]):
                cats["Advertising"] = cats.get("Advertising", 0) + 1
            elif any(w in n_lower for w in ["analytics", "measurement"]):
                cats["Analytics"] = cats.get("Analytics", 0) + 1
            elif any(w in n_lower for w in ["attribution", "adjust", "appsflyer",
                                              "branch", "kochava"]):
                cats["Attribution"] = cats.get("Attribution", 0) + 1
            elif any(w in n_lower for w in ["push", "notification"]):
                cats["Push/Notifications"] = cats.get("Push/Notifications", 0) + 1
            elif any(w in n_lower for w in ["crash", "error", "sentry", "bugsnag"]):
                cats["Crash Reporting"] = cats.get("Crash Reporting", 0) + 1
            else:
                cats["Other"] = cats.get("Other", 0) + 1
        return cats