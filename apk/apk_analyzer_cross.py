"""
apk/apk_analyzer_cross.py

Cross-platform APK static intelligence.
Works on:  Android (Termux) | Linux | Windows

Strategy per platform:
  All platforms:  zipfile + AXML parser + DEX string scan (built-in)
  Linux/Mac:      optionally use aapt/apktool if installed
  Windows:        zipfile + AXML parser (same as Android)

No root required. No external Python packages required.
"""

import os
import re
import sys
import zipfile
import hashlib
import subprocess
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from apk.axml_parser import parse_manifest_bytes, ManifestData
from apk.apk_static_intel import (
    DANGEROUS_API_PATTERNS, TRACKER_SIGNATURES,
    SECRET_PATTERNS, OBFUSCATION_INDICATORS,
    APKIntelReport, DangerousAPIHit, TrackerHit, SecretHit, CertInfo
)
from core.app_analyzer import DANGEROUS_PERMISSIONS


# ─────────────────────────────────────────────────────────────────────────────
# Platform detection
# ─────────────────────────────────────────────────────────────────────────────

def _platform() -> str:
    """Return 'android', 'linux', or 'windows'."""
    if os.path.exists("/data/data/com.termux"):
        return "android"
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    return "linux"


PLATFORM = _platform()


# ─────────────────────────────────────────────────────────────────────────────
# Cross-platform APK Analyser
# ─────────────────────────────────────────────────────────────────────────────

class APKAnalyzerCross:
    """
    Full APK static analysis that works on Android, Linux, and Windows.

    Analysis layers (all platforms):
      1. Manifest   — AXML binary parser (real permissions, components)
      2. DEX scan   — dangerous APIs, tracker SDKs, hardcoded secrets
      3. Structure  — multi-DEX, native libs, assets
      4. Cert       — signing certificate fingerprint

    Optional enhanced analysis (Linux/Mac only, if aapt installed):
      5. aapt dump  — exact resource strings
    """

    def __init__(self):
        self._platform = PLATFORM
        self._aapt_path = self._find_aapt()

    # ── Public API ────────────────────────────────────────────────────────────

    def analyse(self, apk_path: str) -> APKIntelReport:
        report = APKIntelReport(apk_path=apk_path)

        apk_path = os.path.expanduser(apk_path.strip().strip('"\''))
        if not os.path.exists(apk_path):
            report.error = f"File not found: {apk_path}"
            return report

        report.file_size_kb = round(os.path.getsize(apk_path) / 1024, 1)
        report.md5, report.sha256 = self._hash_file(apk_path)

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                namelist = apk.namelist()

                # ── 1. Manifest (AXML binary parser) ─────────────────────
                manifest_data = self._parse_manifest_zip(apk)
                self._apply_manifest(report, manifest_data)

                # ── 2. Structure ──────────────────────────────────────────
                dex_files = [f for f in namelist
                             if re.match(r"classes\d*\.dex$", f)]
                report.dex_count       = len(dex_files)
                report.is_multi_dex    = len(dex_files) > 1

                native_libs = [f for f in namelist if f.endswith(".so")]
                report.native_libs     = native_libs
                report.native_lib_count= len(native_libs)
                report.asset_count     = sum(1 for f in namelist
                                             if f.startswith("assets/"))
                report.is_split_apk   = any("split_" in f for f in namelist)

                # ── 3. DEX scan ───────────────────────────────────────────
                all_dex = ""
                for dex in dex_files[:4]:
                    try:
                        raw = apk.read(dex)
                        all_dex += raw.decode("latin-1", errors="replace")
                    except Exception:
                        pass
                if all_dex:
                    self._scan_dex(all_dex, report)

                # ── 4. Certificate ────────────────────────────────────────
                report.cert = self._extract_cert(apk, namelist)

        except zipfile.BadZipFile:
            report.error = "Not a valid APK (bad zip file)"
            return report
        except Exception as e:
            report.error = str(e)[:120]

        # ── 5. aapt enhancement (Linux/Mac only, optional) ────────────────
        if self._aapt_path and self._platform != "windows":
            self._enhance_with_aapt(report, apk_path)

        # ── Score ─────────────────────────────────────────────────────────
        report.risk_score, report.risk_level, report.risk_factors = \
            self._score(report)

        return report

    # ── Manifest ──────────────────────────────────────────────────────────────

    def _parse_manifest_zip(self, apk: zipfile.ZipFile) -> ManifestData:
        try:
            raw = apk.read("AndroidManifest.xml")
            return parse_manifest_bytes(raw)
        except Exception as e:
            m = ManifestData()
            m.parse_error = str(e)
            return m

    def _apply_manifest(self, report: APKIntelReport, m: ManifestData):
        report.package_name  = m.package_name
        report.version_name  = m.version_name
        report.version_code  = m.version_code
        report.min_sdk       = m.min_sdk
        report.target_sdk    = m.target_sdk
        report.permissions   = list(m.permissions)
        report.activities    = list(m.activities)
        report.services      = list(m.services)
        report.receivers     = list(m.receivers)
        report.providers     = list(m.providers)

        # Mark dangerous permissions
        report.dangerous_permissions = [
            p for p in m.permissions if p in DANGEROUS_PERMISSIONS
        ]
        report.dangerous_perm_count = len(report.dangerous_permissions)
        report.has_boot_receiver = any(
            "RECEIVE_BOOT_COMPLETED" in p for p in m.permissions
        )
        report.has_accessibility = any(
            "BIND_ACCESSIBILITY_SERVICE" in p for p in m.permissions
        ) or any("accessibility" in s.lower() for s in m.services)

    # ── DEX scan ──────────────────────────────────────────────────────────────

    def _scan_dex(self, dex_text: str, report: APKIntelReport):
        lower = dex_text.lower()

        # Dangerous APIs
        for pattern, (desc, severity) in DANGEROUS_API_PATTERNS.items():
            if pattern.lower() in lower:
                report.dangerous_apis.append(
                    DangerousAPIHit(pattern=pattern, description=desc,
                                    severity=severity))

        # Tracker SDKs
        for prefix, name in TRACKER_SIGNATURES.items():
            path_fmt = prefix.lower().replace(".", "/")
            if prefix.lower() in lower or path_fmt in lower:
                cnt = lower.count(prefix.lower())
                report.trackers.append(
                    TrackerHit(package_prefix=prefix,
                               tracker_name=name, match_count=cnt))

        # Hardcoded secrets
        for pattern, label in SECRET_PATTERNS.items():
            matches = re.findall(pattern, dex_text)
            if matches:
                sample = str(matches[0])[:40]
                if len(str(matches[0])) > 40:
                    sample += "..."
                report.secrets.append(
                    SecretHit(pattern_name=label, sample=sample))

        # Embedded URLs and IPs
        urls = re.findall(
            r"https?://[a-zA-Z0-9.\-_/?=&%+:#@]{8,120}", dex_text)
        report.embedded_urls = list(set(urls))[:30]

        ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", dex_text)
        report.embedded_ips = [
            ip for ip in set(ips)
            if not (ip.startswith("10.") or ip.startswith("192.168.")
                    or ip.startswith("127.") or ip.startswith("172."))
        ][:20]

        # Obfuscation indicators
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
            indicators.append(f"{report.native_lib_count} native libraries")
        short_classes = len(re.findall(r"\b[a-z]{1,2}\.[a-z]{1,2}\b",
                                       dex_text[:100000]))
        if short_classes > 50:
            obf_score += 2
            indicators.append(
                f"High density short class names ({short_classes}) → ProGuard/R8")

        report.obfuscation_score      = obf_score
        report.obfuscation_indicators = indicators

    # ── Certificate ───────────────────────────────────────────────────────────

    def _extract_cert(self, apk: zipfile.ZipFile,
                      namelist: list) -> CertInfo:
        info = CertInfo()
        cert_files = [f for f in namelist
                      if f.startswith("META-INF/") and
                      f.upper().endswith((".RSA", ".DSA", ".EC"))]
        if not cert_files:
            return info
        try:
            raw  = apk.read(cert_files[0])
            info.sha256 = hashlib.sha256(raw).hexdigest()
            if b"Android Debug" in raw[:200]:
                info.subject     = "Android Debug"
                info.self_signed = True
            else:
                text = raw.decode("latin-1", errors="replace")
                m = re.search(r"CN=([^\x00,]{1,60})", text)
                if m:
                    info.subject = m.group(1).strip()
                info.self_signed = (not info.issuer or
                                    info.subject == info.issuer)
        except Exception:
            pass
        return info

    # ── aapt enhancement (Linux/Mac) ──────────────────────────────────────────

    def _enhance_with_aapt(self, report: APKIntelReport, apk_path: str):
        """Use aapt to get exact strings if available."""
        try:
            out = subprocess.run(
                [self._aapt_path, "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=15
            ).stdout

            m = re.search(r"package: name='([^']+)'", out)
            if m and not report.package_name:
                report.package_name = m.group(1)

            m = re.search(r"versionName='([^']+)'", out)
            if m and not report.version_name:
                report.version_name = m.group(1)

            m = re.search(r"sdkVersion:'(\d+)'", out)
            if m:
                report.min_sdk = int(m.group(1))

            m = re.search(r"targetSdkVersion:'(\d+)'", out)
            if m:
                report.target_sdk = int(m.group(1))

            # Additional permissions from aapt
            for perm in re.findall(r"uses-permission: name='([^']+)'", out):
                if perm not in report.permissions:
                    report.permissions.append(perm)
                    if perm in DANGEROUS_PERMISSIONS:
                        report.dangerous_permissions.append(perm)
            report.dangerous_perm_count = len(report.dangerous_permissions)

        except Exception:
            pass

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score(self, report: APKIntelReport) -> tuple[int, str, list]:
        score   = 0
        factors = []

        score += report.dangerous_perm_count * 3
        if report.dangerous_perm_count >= 8:
            factors.append(f"{report.dangerous_perm_count} dangerous permissions")

        api_score = sum(
            {"CRITICAL": 8, "HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(h.severity, 1)
            for h in report.dangerous_apis
        )
        score += min(api_score, 40)
        if any(h.severity == "CRITICAL" for h in report.dangerous_apis):
            factors.append("Critical dangerous API usage")

        score += len(report.trackers) * 2
        if len(report.trackers) >= 4:
            factors.append(f"{len(report.trackers)} embedded tracker SDKs")

        score += len(report.secrets) * 5
        if report.secrets:
            factors.append(f"{len(report.secrets)} potential hardcoded secrets")

        score += report.obfuscation_score * 3
        if report.obfuscation_score >= 3:
            factors.append("Heavy obfuscation detected")

        if report.has_boot_receiver:
            score += 5
            factors.append("Boot receiver (persistence)")

        if report.has_accessibility:
            score += 10
            factors.append("Accessibility service (spyware/keylogger risk)")

        if report.is_multi_dex:
            score += 5

        if report.embedded_ips:
            score += len(report.embedded_ips) * 2
            factors.append(f"{len(report.embedded_ips)} hardcoded public IPs")

        if score >= 60:   level = "CRITICAL"
        elif score >= 35: level = "HIGH"
        elif score >= 15: level = "MEDIUM"
        else:             level = "LOW"

        return score, level, factors[:6]

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _hash_file(path: str) -> tuple[str, str]:
        md5    = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()

    @staticmethod
    def _find_aapt() -> Optional[str]:
        """Find aapt binary on the system."""
        candidates = ["aapt", "aapt2"]
        # Android SDK paths
        sdk_paths = [
            os.path.expanduser("~/Android/Sdk/build-tools"),
            "C:\\Users\\%USERNAME%\\AppData\\Local\\Android\\Sdk\\build-tools",
            "/usr/local/lib/android/sdk/build-tools",
        ]
        for cand in candidates:
            r = subprocess.run(
                ["which" if PLATFORM != "windows" else "where", cand],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                return r.stdout.strip().splitlines()[0]
        return None

    def print_report(self, report: APKIntelReport):
        """Rich-formatted console report."""
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            console = Console()
        except ImportError:
            self._plain_report(report)
            return

        risk_color = {"CRITICAL": "bold red", "HIGH": "red",
                      "MEDIUM": "yellow", "LOW": "green"}.get(
                          report.risk_level, "white")

        console.print(Panel(
            f"[bold]Package    :[/bold] {report.package_name or '(unknown)'}\n"
            f"[bold]Version    :[/bold] {report.version_name} ({report.version_code})\n"
            f"[bold]File       :[/bold] {Path(report.apk_path).name}  ({report.file_size_kb} KB)\n"
            f"[bold]SHA256     :[/bold] {report.sha256[:32]}…\n"
            f"[bold]Min SDK    :[/bold] {report.min_sdk}  "
            f"[bold]Target SDK :[/bold] {report.target_sdk}\n"
            f"[bold]DEX files  :[/bold] {report.dex_count}"
            f"{'  (multi-DEX)' if report.is_multi_dex else ''}\n"
            f"[bold]Native libs:[/bold] {report.native_lib_count}\n"
            f"[bold]Risk Score :[/bold] {report.risk_score}\n"
            f"[bold]Risk Level :[/bold] [{risk_color}]{report.risk_level}[/{risk_color}]",
            title=f"[bold]APK Intelligence — {Path(report.apk_path).name}[/bold]",
            border_style=risk_color,
        ))

        if report.parse_error_manifest:
            console.print(f"[yellow]⚠ Manifest parse warning: {report.parse_error_manifest}[/yellow]")

        if report.risk_factors:
            console.print("\n[bold red]Risk Factors:[/bold red]")
            for f in report.risk_factors:
                console.print(f"  • {f}")

        if report.dangerous_permissions:
            console.print(f"\n[red]Dangerous Permissions "
                          f"({report.dangerous_perm_count}):[/red]")
            for p in report.dangerous_permissions[:10]:
                console.print(f"  • {p}")

        if report.dangerous_apis:
            console.print(f"\n[red]Dangerous APIs ({len(report.dangerous_apis)}):[/red]")
            for api in report.dangerous_apis[:10]:
                s = {"CRITICAL":"bold red","HIGH":"red",
                     "MEDIUM":"yellow","LOW":"dim"}.get(api.severity,"")
                console.print(f"  [{s}]{api.severity:<8}[/{s}] {api.description}")

        if report.trackers:
            console.print(f"\n[yellow]Embedded Trackers ({len(report.trackers)}):[/yellow]")
            for t in report.trackers:
                console.print(f"  • {t.tracker_name}")

        if report.secrets:
            console.print(f"\n[red]Hardcoded Secrets ({len(report.secrets)}):[/red]")
            for s in report.secrets[:6]:
                console.print(f"  • {s.pattern_name}  [dim]{s.sample}[/dim]")

        if report.embedded_ips:
            console.print(f"\n[yellow]Hardcoded IPs ({len(report.embedded_ips)}):[/yellow]")
            for ip in report.embedded_ips[:8]:
                console.print(f"  • {ip}")

        if report.obfuscation_indicators:
            console.print(f"\n[dim]Obfuscation indicators:[/dim]")
            for ind in report.obfuscation_indicators:
                console.print(f"  [dim]• {ind}[/dim]")

    def _plain_report(self, report: APKIntelReport):
        print(f"\n=== APK Analysis: {report.apk_path} ===")
        print(f"Package   : {report.package_name}")
        print(f"Risk      : {report.risk_level} (score={report.risk_score})")
        print(f"Perms     : {report.dangerous_perm_count} dangerous")
        print(f"Trackers  : {len(report.trackers)}")
        print(f"Secrets   : {len(report.secrets)}")
        if report.error:
            print(f"Error     : {report.error}")


# ── Patch APKIntelReport to add parse_error_manifest field ───────────────────
# (backwards compatible — only used by cross analyser)
if not hasattr(APKIntelReport, "parse_error_manifest"):
    from dataclasses import fields as dc_fields
    APKIntelReport.parse_error_manifest = ""