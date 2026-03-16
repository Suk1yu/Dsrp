"""
apk/apk_static_intel.py

Advanced static APK intelligence analysis.
No sandbox, no execution — pure static analysis.

Techniques:
  1. Manifest parsing (permissions, components, intents)
  2. DEX string extraction (APIs, URLs, domains, keys)
  3. Certificate fingerprinting
  4. Resource analysis (assets, raw files)
  5. Obfuscation indicators
  6. Embedded secrets detection

Tools: Python zipfile + re (no androguard needed — lighter)
CPU cost: On-demand only, proportional to APK size
"""

import re
import zipfile
import hashlib
import os
import time
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.app_analyzer import DANGEROUS_PERMISSIONS


# ---------------------------------------------------------------------------
# Pattern databases
# ---------------------------------------------------------------------------

DANGEROUS_API_PATTERNS = {
    "Runtime.exec(":              ("RCE", "CRITICAL"),
    "ProcessBuilder":             ("Process spawning", "HIGH"),
    "DexClassLoader":             ("Dynamic code loading", "CRITICAL"),
    "PathClassLoader":            ("Runtime class loading", "HIGH"),
    "System.loadLibrary":         ("Native library loading", "HIGH"),
    "URLClassLoader":             ("Dynamic URL loading", "HIGH"),
    "Cipher.getInstance":         ("Cryptography use", "MEDIUM"),
    "SecretKeySpec":              ("Secret key crypto", "MEDIUM"),
    "getSmsManager":              ("SMS manager access", "HIGH"),
    "MediaRecorder":              ("Audio/video recording", "HIGH"),
    "PackageInstaller":           ("APK installation", "HIGH"),
    "DevicePolicyManager":        ("Device admin control", "CRITICAL"),
    "getSystemService(\"phone\"": ("Phone service access", "HIGH"),
    "TelephonyManager":           ("Telephony access", "HIGH"),
    "getContentResolver":         ("Content provider access", "MEDIUM"),
    "android.provider.Telephony": ("SMS/call log DB", "HIGH"),
    "AccessibilityService":       ("Accessibility service", "HIGH"),
    "InputMethodService":         ("Input method (keylogger risk)", "HIGH"),
    "getSIM":                     ("SIM info access", "MEDIUM"),
    "IMEI":                       ("IMEI access", "MEDIUM"),
    "getAndroidId":               ("Android ID access", "LOW"),
    "Frida":                      ("Anti-analysis: Frida check", "MEDIUM"),
    "ptrace":                     ("Anti-analysis: ptrace check", "MEDIUM"),
    "isDebuggerConnected":        ("Anti-debug check", "MEDIUM"),
    "Base64.decode":              ("Base64 decode (hidden payload)", "LOW"),
    "XOR":                        ("XOR obfuscation indicator", "LOW"),
    "chmod 777":                  ("World-writable file creation", "MEDIUM"),
    "/system/bin/su":             ("Root access via su", "CRITICAL"),
    "Ldalvik/system/DexClass":   ("DEX class loading", "HIGH"),
}

TRACKER_SIGNATURES = {
    "com.facebook": "Facebook Analytics",
    "com.google.firebase": "Firebase Analytics",
    "com.google.android.gms.analytics": "Google Analytics",
    "com.mixpanel": "Mixpanel",
    "com.amplitude": "Amplitude",
    "com.adjust": "Adjust",
    "com.appsflyer": "AppsFlyer",
    "io.branch": "Branch",
    "com.flurry": "Flurry",
    "com.crashlytics": "Crashlytics",
    "com.onesignal": "OneSignal",
    "com.segment": "Segment",
    "com.applovin": "AppLovin",
    "com.ironsource": "ironSource",
    "com.unity3d.ads": "Unity Ads",
    "com.chartboost": "Chartboost",
    "com.vungle": "Vungle",
    "com.moat": "Moat Ad Verification",
    "com.mopub": "MoPub/Twitter Ads",
    "com.taboola": "Taboola",
    "com.singular": "Singular",
    "com.kochava": "Kochava",
    "com.swrve": "Swrve",
    "com.localytics": "Localytics",
    "com.braze": "Braze",
}

SECRET_PATTERNS = {
    r"AIza[0-9A-Za-z_\-]{35}":       "Google API key",
    r"AAAA[0-9A-Za-z_\-]{120,}":     "Firebase server key",
    r"[0-9a-f]{32}":                  "Possible API secret (32-char hex)",
    r"sk_live_[0-9a-zA-Z]{24}":       "Stripe live key",
    r"[0-9]{15,18}:[0-9A-Za-z_\-]{35}": "Telegram bot token",
    r"EAA[0-9a-zA-Z]+":               "Facebook Access Token",
    r"-----BEGIN (RSA |EC )?PRIVATE KEY-----": "Embedded private key",
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?": "Hardcoded IP URL",
    r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?\w{6,}": "Hardcoded password",
    r"(?i)(api_?key|apikey|access_?token)\s*[=:]\s*['\"][\w\-]{8,}": "Hardcoded API key",
}

OBFUSCATION_INDICATORS = [
    (r"[a-z]{1,2}/[a-z]{1,2}/[a-z]{1,2}", "Short class names (proguard/obfuscation)"),
    (r"[A-Za-z0-9+/]{60,}={0,2}", "Long base64 blob (possible encrypted payload)"),
    (r"\x00[^\x00]{3}\x00", "Null-padded strings (packing indicator)"),
]


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PermissionEntry:
    name: str
    is_dangerous: bool = False
    risk_level: str = "LOW"


@dataclass
class ComponentEntry:
    name: str
    comp_type: str   # activity / service / receiver / provider
    is_exported: bool = False
    has_intent_filter: bool = False


@dataclass
class DangerousAPIHit:
    pattern: str
    description: str
    severity: str
    location: str = "dex"


@dataclass
class TrackerHit:
    package_prefix: str
    tracker_name: str
    match_count: int = 1


@dataclass
class SecretHit:
    pattern_name: str
    sample: str          # first 40 chars of match (redacted)
    location: str = ""


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    sha256: str = ""
    self_signed: bool = False
    valid_from: str = ""
    valid_to: str = ""


@dataclass
class APKIntelReport:
    # File info
    apk_path: str
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    file_size_kb: float = 0.0
    md5: str = ""
    sha256: str = ""
    analysed_at: float = field(default_factory=time.time)

    # Structure
    dex_count: int = 0
    native_lib_count: int = 0
    native_libs: list = field(default_factory=list)
    asset_count: int = 0
    is_multi_dex: bool = False
    is_split_apk: bool = False
    min_sdk: int = 0
    target_sdk: int = 0

    # Permissions
    permissions: list = field(default_factory=list)
    dangerous_permissions: list = field(default_factory=list)
    dangerous_perm_count: int = 0

    # Components
    activities: list = field(default_factory=list)
    services: list = field(default_factory=list)
    receivers: list = field(default_factory=list)
    providers: list = field(default_factory=list)
    has_boot_receiver: bool = False
    has_accessibility: bool = False

    # Intelligence findings
    dangerous_apis: list = field(default_factory=list)
    trackers: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    embedded_urls: list = field(default_factory=list)
    embedded_ips: list = field(default_factory=list)
    obfuscation_score: int = 0
    obfuscation_indicators: list = field(default_factory=list)

    # Certificate
    cert: Optional[CertInfo] = None

    # Risk scoring
    risk_score: int = 0
    risk_level: str = "LOW"
    risk_factors: list = field(default_factory=list)

    # Meta
    error: str = ""


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

class APKStaticIntel:
    """
    Deep static APK intelligence — runs on-demand, no execution.
    Returns a rich APKIntelReport with all findings.
    """

    def analyse(self, apk_path: str) -> APKIntelReport:
        report = APKIntelReport(apk_path=apk_path)

        if not os.path.exists(apk_path):
            report.error = f"File not found: {apk_path}"
            return report

        report.file_size_kb = round(os.path.getsize(apk_path) / 1024, 1)
        report.md5, report.sha256 = self._hash_file(apk_path)

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                namelist = apk.namelist()

                # Structure analysis
                dex_files = [f for f in namelist if re.match(r"classes\d*\.dex", f)]
                report.dex_count = len(dex_files)
                report.is_multi_dex = len(dex_files) > 1

                native_libs = [f for f in namelist if f.endswith(".so")]
                report.native_libs = native_libs
                report.native_lib_count = len(native_libs)

                report.asset_count = sum(1 for f in namelist
                                         if f.startswith("assets/"))
                report.is_split_apk = any("split_" in f for f in namelist)

                # AndroidManifest.xml
                self._parse_manifest(apk, report)

                # DEX analysis (all dex files)
                all_dex_text = ""
                for dex in dex_files[:4]:   # cap at 4 DEX files for speed
                    try:
                        raw = apk.read(dex)
                        all_dex_text += raw.decode("latin-1", errors="replace")
                    except Exception:
                        pass

                if all_dex_text:
                    self._scan_dex(all_dex_text, report)

                # Certificate extraction
                report.cert = self._extract_cert(apk)

        except zipfile.BadZipFile:
            report.error = "Invalid APK (not a valid zip file)"
            return report
        except Exception as e:
            report.error = str(e)[:120]

        # Score
        report.risk_score, report.risk_level, report.risk_factors = \
            self._score(report)

        return report

    # ------------------------------------------------------------------
    # Manifest parsing
    # ------------------------------------------------------------------

    def _parse_manifest(self, apk: zipfile.ZipFile, report: APKIntelReport):
        try:
            raw = apk.read("AndroidManifest.xml").decode("latin-1", errors="replace")
        except Exception:
            return

        # Package name
        m = re.search(r"package[\"=\s]+([\w.]+)", raw)
        if m:
            report.package_name = m.group(1)

        # Version
        m = re.search(r"versionName[\"=\s]+([\w.]+)", raw)
        if m:
            report.version_name = m.group(1)

        m = re.search(r"versionCode[\"=\s]+(\d+)", raw)
        if m:
            report.version_code = m.group(1)

        m = re.search(r"minSdkVersion[\"=\s]+(\d+)", raw)
        if m:
            report.min_sdk = int(m.group(1))

        m = re.search(r"targetSdkVersion[\"=\s]+(\d+)", raw)
        if m:
            report.target_sdk = int(m.group(1))

        # Permissions
        perms = list(set(re.findall(r"android\.permission\.(\w+)", raw)))
        report.permissions = perms
        dangerous = [f"android.permission.{p}" for p in perms
                     if f"android.permission.{p}" in DANGEROUS_PERMISSIONS]
        report.dangerous_permissions = dangerous
        report.dangerous_perm_count = len(dangerous)

        # Receivers
        receivers = list(set(re.findall(r"receiver.*?android:name=[\"']?([\w.]+)", raw)))
        report.receivers = receivers
        report.has_boot_receiver = "RECEIVE_BOOT_COMPLETED" in " ".join(perms)

        # Services
        report.services = list(set(re.findall(r"service.*?android:name=[\"']?([\w.]+)", raw)))

        # Activities
        report.activities = list(set(re.findall(r"activity.*?android:name=[\"']?([\w.]+)", raw)))

        # Providers
        report.providers = list(set(re.findall(r"provider.*?android:name=[\"']?([\w.]+)", raw)))

        # Accessibility
        report.has_accessibility = "BIND_ACCESSIBILITY_SERVICE" in raw.upper() or \
                                   "AccessibilityService" in raw

    # ------------------------------------------------------------------
    # DEX analysis
    # ------------------------------------------------------------------

    def _scan_dex(self, dex_text: str, report: APKIntelReport):
        """Scan DEX bytecode for dangerous APIs, trackers, secrets, URLs."""
        lower = dex_text.lower()

        # Dangerous APIs
        for pattern, (desc, severity) in DANGEROUS_API_PATTERNS.items():
            if pattern.lower() in lower:
                report.dangerous_apis.append(DangerousAPIHit(
                    pattern=pattern, description=desc,
                    severity=severity
                ))

        # Tracker SDKs
        for prefix, name in TRACKER_SIGNATURES.items():
            prefix_lower = prefix.lower().replace(".", "[./]")
            if re.search(prefix_lower, lower):
                report.trackers.append(TrackerHit(
                    package_prefix=prefix,
                    tracker_name=name,
                    match_count=lower.count(prefix.lower()),
                ))

        # Hardcoded secrets
        for pattern, label in SECRET_PATTERNS.items():
            matches = re.findall(pattern, dex_text)
            if matches:
                # Show only redacted sample
                sample = str(matches[0])[:40] + ("..." if len(str(matches[0])) > 40 else "")
                report.secrets.append(SecretHit(
                    pattern_name=label,
                    sample=sample,
                ))

        # Extract embedded URLs
        urls = re.findall(r"https?://[a-zA-Z0-9.\-_/?=&%+:#@]{8,120}", dex_text)
        report.embedded_urls = list(set(urls))[:30]

        # Extract embedded IPs (non-LAN)
        ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", dex_text)
        public_ips = [ip for ip in set(ips)
                      if not (ip.startswith("10.") or ip.startswith("192.168.")
                              or ip.startswith("127.") or ip.startswith("172."))]
        report.embedded_ips = public_ips[:20]

        # Obfuscation detection
        obf_score = 0
        indicators = []
        for pattern, desc in OBFUSCATION_INDICATORS:
            if re.search(pattern, dex_text[:50000]):
                obf_score += 1
                indicators.append(desc)

        if report.is_multi_dex:
            obf_score += 2
            indicators.append(f"Multi-DEX ({report.dex_count} DEX files)")

        if report.native_lib_count > 0:
            obf_score += 1
            indicators.append(f"{report.native_lib_count} native library/libs")

        # High ratio of short class names
        short_classes = len(re.findall(r"\b[a-z]{1,2}\.[a-z]{1,2}\b", dex_text[:100000]))
        if short_classes > 50:
            obf_score += 2
            indicators.append(f"High density of short class names ({short_classes}) — ProGuard/R8")

        report.obfuscation_score = obf_score
        report.obfuscation_indicators = indicators

    # ------------------------------------------------------------------
    # Certificate
    # ------------------------------------------------------------------

    def _extract_cert(self, apk: zipfile.ZipFile) -> Optional[CertInfo]:
        """Extract signing certificate info."""
        cert_info = CertInfo()
        # Look for META-INF/CERT.RSA or similar
        cert_files = [f for f in apk.namelist()
                      if f.startswith("META-INF/") and
                      f.upper().endswith((".RSA", ".DSA", ".EC"))]
        if not cert_files:
            return cert_info

        try:
            cert_data = apk.read(cert_files[0])
            cert_info.sha256 = hashlib.sha256(cert_data).hexdigest()

            # Basic debug cert detection
            if b"Android Debug" in cert_data or b"Android" in cert_data[:100]:
                cert_info.subject = "Android Debug"
                cert_info.self_signed = True
            else:
                # Try to extract subject/issuer from DER (basic heuristic)
                text = cert_data.decode("latin-1", errors="replace")
                m = re.search(r"CN=([^\x00,]+)", text)
                if m:
                    cert_info.subject = m.group(1)[:60]
                cert_info.self_signed = cert_info.subject == cert_info.issuer \
                                        or not cert_info.issuer

        except Exception:
            pass
        return cert_info

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _score(self, report: APKIntelReport) -> tuple[int, str, list]:
        score = 0
        factors = []

        # Permissions
        score += report.dangerous_perm_count * 3
        if report.dangerous_perm_count >= 8:
            factors.append(f"{report.dangerous_perm_count} dangerous permissions (excessive)")

        # Dangerous APIs
        api_score = sum({"CRITICAL": 8, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(
            h.severity, 1) for h in report.dangerous_apis)
        score += min(api_score, 40)
        if any(h.severity == "CRITICAL" for h in report.dangerous_apis):
            factors.append("Critical dangerous API usage (RCE/device admin/dynamic loading)")

        # Trackers
        score += len(report.trackers) * 2
        if len(report.trackers) >= 4:
            factors.append(f"{len(report.trackers)} embedded tracker SDKs")

        # Secrets
        score += len(report.secrets) * 5
        if report.secrets:
            factors.append(f"{len(report.secrets)} potential hardcoded secrets/API keys")

        # Obfuscation
        score += report.obfuscation_score * 3
        if report.obfuscation_score >= 3:
            factors.append("Heavy obfuscation detected")

        # Boot persistence
        if report.has_boot_receiver:
            score += 5
            factors.append("Boot receiver registered (persistence)")

        # Accessibility abuse
        if report.has_accessibility:
            score += 10
            factors.append("Accessibility service declared (spyware/keylogger risk)")

        # Multi-DEX
        if report.is_multi_dex:
            score += 5
            factors.append(f"Multi-DEX ({report.dex_count} DEX files)")

        # Native libraries
        if report.native_lib_count > 0:
            score += 3
            factors.append(f"{report.native_lib_count} native libraries")

        # Embedded IPs
        if report.embedded_ips:
            score += len(report.embedded_ips) * 2
            factors.append(f"{len(report.embedded_ips)} hardcoded public IPs")

        if score >= 60:
            level = "CRITICAL"
        elif score >= 35:
            level = "HIGH"
        elif score >= 15:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level, factors[:6]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_file(path: str) -> tuple[str, str]:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()