"""
network/ssl_tls_analyzer.py

SSL/TLS Security Analyzer — Cross-Platform (Android / Linux / Windows)

Three analysis modes:
  1. APK Static Scan    — find SSL bypass patterns in DEX bytecode
  2. Live Connection    — test actual HTTPS endpoints for weak TLS
  3. System SSL Audit   — check OS trust store, CA count, TLS config

Detects:
  - TrustAllCerts / NullTrustManager (MITM vulnerability)
  - allowAllHostnames / HostnameVerifier bypass
  - Expired or self-signed certificates
  - Weak cipher suites (RC4, DES, MD5, TLS 1.0/1.1)
  - Certificate pinning bypass patterns
  - Network Security Config misconfig (Android)
  - SSL stripping indicators
"""

import os
import re
import ssl
import socket
import time
import zipfile
import threading
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone


# ─────────────────────────────────────────────────────────────────────────────
# SSL bypass patterns (found in DEX bytecode)
# ─────────────────────────────────────────────────────────────────────────────

SSL_BYPASS_PATTERNS = {
    # TrustManager bypass
    "X509TrustManager":               ("TrustManager implementation (check if it validates)", "MEDIUM"),
    "checkServerTrusted":              ("Custom checkServerTrusted — may skip validation", "HIGH"),
    "TrustAllCerts":                   ("TrustAllCerts pattern — accepts all certificates!", "CRITICAL"),
    "trustAllCerts":                   ("trustAllCerts — accepts all certificates!", "CRITICAL"),
    "ALLOW_ALL_HOSTNAME_VERIFIER":     ("AllowAllHostnames — no hostname validation!", "CRITICAL"),
    "allowAllHostnames":               ("Allows all hostnames — no hostname validation!", "CRITICAL"),
    "AllowAllHostnameVerifier":        ("AllowAllHostnameVerifier — MITM vulnerable!", "CRITICAL"),
    "NullTrustManager":                ("NullTrustManager — ignores all cert errors!", "CRITICAL"),
    "TRUST_ALL":                       ("TRUST_ALL constant — certificate validation disabled", "HIGH"),
    "hostnameVerifier.*return.*true":  ("Hostname verifier always returns true", "CRITICAL"),

    # Certificate pinning bypass
    "TrustManagerImpl":                ("Custom TrustManagerImpl — verify it pins correctly", "MEDIUM"),
    "CertificatePinner":               ("CertificatePinner (OkHttp) — good if used correctly", "LOW"),
    "disable.*pinning":                ("Certificate pinning disabled", "HIGH"),
    "bypass.*pinning":                 ("Certificate pinning bypass", "CRITICAL"),
    "DISABLE_CERTIFICATE_PINNING":     ("Certificate pinning explicitly disabled", "CRITICAL"),

    # HttpClient / OkHttp misconfig
    "HttpsURLConnection.*setDefault":  ("Default HTTPS config override", "MEDIUM"),
    "SSLSocketFactory.*getInsecure":   ("getInsecureSSLSocketFactory — NO validation", "CRITICAL"),
    "SSLContext.*TLS.*NONE":           ("SSLContext with no validation", "HIGH"),
    "onReceivedSslError.*proceed":     ("WebView proceeds on SSL errors — MITM vulnerable!", "CRITICAL"),
    "handler.proceed":                 ("SSL error handler proceeds without validation", "HIGH"),

    # Network Security Config
    "cleartextTrafficPermitted.*true": ("Cleartext HTTP allowed — traffic not encrypted", "HIGH"),
    "network-security-config":         ("Custom network security config present", "LOW"),
    "debug-overrides":                 ("Debug SSL overrides in network security config", "MEDIUM"),
    "base-config.*trust-anchors":      ("Custom trust anchors — may include user CAs", "MEDIUM"),
}

# TLS version info
WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}
STRONG_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "ADH", "AECDH", "aNULL", "eNULL",
}

# Domains to test for live TLS check
DEFAULT_TEST_DOMAINS = [
    "google.com",
    "facebook.com",
    "api.twitter.com",
    "graph.facebook.com",
    "api.mixpanel.com",
]


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SSLBypassHit:
    pattern: str
    description: str
    severity: str
    location: str = "dex"     # dex / manifest / network_security_config
    line_sample: str = ""


@dataclass
class CertificateInfo:
    domain: str
    subject: str = ""
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    is_expired: bool = False
    is_self_signed: bool = False
    days_remaining: int = 0
    tls_version: str = ""
    cipher_suite: str = ""
    has_weak_cipher: bool = False
    has_weak_tls: bool = False
    error: str = ""
    risk: str = "OK"       # OK / LOW / MEDIUM / HIGH / CRITICAL


@dataclass
class APKSSLReport:
    apk_path: str
    package_name: str = ""
    bypass_hits: list = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    network_security_config: dict = field(default_factory=dict)
    uses_cleartext: bool = False
    risk_level: str = "LOW"
    risk_score: int = 0
    error: str = ""


@dataclass
class LiveSSLReport:
    domains_tested: list = field(default_factory=list)
    certificates: list = field(default_factory=list)
    failed_domains: list = field(default_factory=list)
    weak_tls_count: int = 0
    expired_count: int = 0
    self_signed_count: int = 0
    risk_level: str = "LOW"


@dataclass
class SystemSSLReport:
    platform: str = ""
    ca_count: int = 0
    user_ca_count: int = 0
    system_tls_min: str = ""
    supports_tls13: bool = False
    supports_tls12: bool = False
    findings: list = field(default_factory=list)
    risk_level: str = "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Main analyser
# ─────────────────────────────────────────────────────────────────────────────

class SSLTLSAnalyzer:
    """
    Cross-platform SSL/TLS security analyser.

    Usage:
        analyzer = SSLTLSAnalyzer()
        apk_report  = analyzer.scan_apk("app.apk")
        live_report = analyzer.scan_live_connections(["google.com"])
        sys_report  = analyzer.audit_system()
    """

    def __init__(self):
        self._platform = self._detect_platform()

    # ── APK scan ──────────────────────────────────────────────────────────────

    def scan_apk(self, apk_path: str) -> APKSSLReport:
        """
        Scan an APK file for SSL/TLS bypass patterns.
        Works on Android, Linux, and Windows — no extra tools needed.
        """
        report = APKSSLReport(apk_path=apk_path)
        apk_path = os.path.expanduser(apk_path.strip().strip('"\''))

        if not os.path.exists(apk_path):
            report.error = f"File not found: {apk_path}"
            return report

        try:
            with zipfile.ZipFile(apk_path, "r") as apk:
                namelist = apk.namelist()

                # Package name from manifest
                try:
                    raw = apk.read("AndroidManifest.xml")
                    report.package_name = self._extract_package_name(raw)
                    # Check cleartext traffic flag
                    text = raw.decode("latin-1", errors="replace")
                    if "usesCleartextTraffic" in text and "true" in text:
                        report.uses_cleartext = True
                except Exception:
                    pass

                # Network Security Config
                nsc_files = [f for f in namelist
                             if "network_security_config" in f.lower()
                             or "network-security-config" in f.lower()]
                if nsc_files:
                    try:
                        nsc_raw = apk.read(nsc_files[0]).decode(
                            "utf-8", errors="replace")
                        report.network_security_config = \
                            self._parse_network_security_config(nsc_raw)
                    except Exception:
                        pass

                # DEX scan
                dex_files = [f for f in namelist
                             if re.match(r"classes\d*\.dex$", f)]
                all_dex = ""
                for dex in dex_files[:4]:
                    try:
                        all_dex += apk.read(dex).decode("latin-1",
                                                          errors="replace")
                    except Exception:
                        pass

                if all_dex:
                    hits = self._scan_dex_ssl(all_dex)
                    report.bypass_hits = hits

        except zipfile.BadZipFile:
            report.error = "Not a valid APK"
            return report
        except Exception as e:
            report.error = str(e)[:100]

        # Scoring
        report.critical_count = sum(1 for h in report.bypass_hits
                                    if h.severity == "CRITICAL")
        report.high_count     = sum(1 for h in report.bypass_hits
                                    if h.severity == "HIGH")
        report.medium_count   = sum(1 for h in report.bypass_hits
                                    if h.severity == "MEDIUM")

        score = (report.critical_count * 15 +
                 report.high_count * 8 +
                 report.medium_count * 3)
        if report.uses_cleartext:
            score += 10
            report.bypass_hits.insert(0, SSLBypassHit(
                pattern="usesCleartextTraffic",
                description="App allows unencrypted HTTP traffic",
                severity="HIGH", location="manifest",
            ))

        # NSC issues
        nsc = report.network_security_config
        if nsc.get("debug_overrides"):
            score += 8
        if nsc.get("trust_user_certs"):
            score += 12
            report.bypass_hits.append(SSLBypassHit(
                pattern="trustUserCerts",
                description="App trusts user-installed CAs — MITM via user cert possible",
                severity="HIGH", location="network_security_config",
            ))

        if score >= 30:   report.risk_level = "CRITICAL"
        elif score >= 15: report.risk_level = "HIGH"
        elif score >= 5:  report.risk_level = "MEDIUM"
        else:             report.risk_level = "LOW"

        report.risk_score = score
        return report

    def _scan_dex_ssl(self, dex_text: str) -> list[SSLBypassHit]:
        hits = []
        lower = dex_text.lower()
        seen  = set()

        for pattern, (desc, severity) in SSL_BYPASS_PATTERNS.items():
            p_lower = pattern.lower()
            # Use regex for patterns with wildcards
            if ".*" in pattern:
                try:
                    if re.search(p_lower, lower):
                        key = desc
                        if key not in seen:
                            seen.add(key)
                            hits.append(SSLBypassHit(
                                pattern=pattern,
                                description=desc,
                                severity=severity,
                                location="dex",
                            ))
                except Exception:
                    pass
            else:
                if p_lower in lower:
                    key = desc
                    if key not in seen:
                        seen.add(key)
                        hits.append(SSLBypassHit(
                            pattern=pattern,
                            description=desc,
                            severity=severity,
                            location="dex",
                        ))

        # Sort by severity
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        hits.sort(key=lambda h: order.get(h.severity, 4))
        return hits

    def _parse_network_security_config(self, xml: str) -> dict:
        nsc = {
            "debug_overrides":  "debug-overrides" in xml,
            "trust_user_certs": "user" in xml and "certificates" in xml,
            "cleartext_domains": re.findall(
                r'cleartextTrafficPermitted[^>]*?>(.*?)<', xml),
            "pinned_domains": len(re.findall(r"<pin-set", xml)) > 0,
        }
        return nsc

    @staticmethod
    def _extract_package_name(manifest_bytes: bytes) -> str:
        # Try text XML
        try:
            text = manifest_bytes.decode("utf-8", errors="replace")
            m = re.search(r'package\s*=\s*["\']([^"\']+)["\']', text)
            if m:
                return m.group(1)
        except Exception:
            pass
        # Binary AXML
        try:
            from apk.axml_parser import parse_manifest_bytes
            m = parse_manifest_bytes(manifest_bytes)
            return m.package_name
        except Exception:
            pass
        return ""

    # ── Live connection check ─────────────────────────────────────────────────

    def scan_live_connections(self,
                               domains: list = None,
                               port: int = 443,
                               timeout: float = 8.0) -> LiveSSLReport:
        """
        Test real HTTPS connections for TLS version, cipher strength,
        certificate validity, and expiry.
        """
        domains = domains or DEFAULT_TEST_DOMAINS
        report  = LiveSSLReport(domains_tested=domains)

        for domain in domains:
            cert_info = self._check_cert(domain, port, timeout)
            report.certificates.append(cert_info)
            if cert_info.error and "refused" not in cert_info.error:
                report.failed_domains.append(domain)
            if cert_info.has_weak_tls:
                report.weak_tls_count += 1
            if cert_info.is_expired:
                report.expired_count += 1
            if cert_info.is_self_signed:
                report.self_signed_count += 1

        # Overall risk
        issues = (report.weak_tls_count + report.expired_count * 2 +
                  report.self_signed_count * 2)
        if issues >= 4:   report.risk_level = "HIGH"
        elif issues >= 2: report.risk_level = "MEDIUM"
        elif issues >= 1: report.risk_level = "LOW"
        else:             report.risk_level = "SAFE"

        return report

    def _check_cert(self, domain: str, port: int,
                     timeout: float) -> CertificateInfo:
        info = CertificateInfo(domain=domain)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                    (domain, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    info.tls_version = ssock.version() or ""
                    cipher = ssock.cipher()
                    if cipher:
                        info.cipher_suite = cipher[0]
                        info.has_weak_cipher = any(
                            w in cipher[0].upper() for w in WEAK_CIPHERS)

                    cert = ssock.getpeercert()
                    if cert:
                        subj = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        info.subject = subj.get("commonName", "")
                        info.issuer  = issuer.get("commonName", "")
                        info.is_self_signed = (info.subject == info.issuer)

                        # Expiry
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            try:
                                exp = datetime.strptime(
                                    not_after, "%b %d %H:%M:%S %Y %Z")
                                exp = exp.replace(tzinfo=timezone.utc)
                                now = datetime.now(timezone.utc)
                                info.valid_to = not_after
                                days = (exp - now).days
                                info.days_remaining = days
                                info.is_expired = days < 0
                            except Exception:
                                pass

                    info.has_weak_tls = info.tls_version in WEAK_TLS_VERSIONS

                    # Risk
                    if info.is_expired or info.is_self_signed:
                        info.risk = "CRITICAL"
                    elif info.has_weak_tls:
                        info.risk = "HIGH"
                    elif info.has_weak_cipher:
                        info.risk = "MEDIUM"
                    elif info.days_remaining < 30 and info.days_remaining >= 0:
                        info.risk = "MEDIUM"
                        info.risk = "LOW"
                    else:
                        info.risk = "OK"

        except ssl.SSLError as e:
            info.error = f"SSL error: {str(e)[:60]}"
            info.risk = "HIGH"
        except ConnectionRefusedError:
            info.error = "Connection refused"
        except socket.timeout:
            info.error = "Timeout"
        except Exception as e:
            info.error = str(e)[:60]

        return info

    # ── System SSL audit ──────────────────────────────────────────────────────

    def audit_system(self) -> SystemSSLReport:
        """Audit the OS SSL/TLS configuration."""
        report = SystemSSLReport(platform=self._platform)

        # Python's ssl module capabilities
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        report.supports_tls12 = True   # Python 3.x always supports
        try:
            # TLS 1.3 support
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            report.supports_tls13 = True
        except AttributeError:
            report.supports_tls13 = False
        except Exception:
            report.supports_tls13 = False

        # Count trusted CAs
        try:
            import certifi
            with open(certifi.where()) as f:
                report.ca_count = f.read().count("BEGIN CERTIFICATE")
        except ImportError:
            # Count from system cert store
            report.ca_count = len(ssl.create_default_context().get_ca_certs())

        # Android: check user-installed CAs
        if self._platform == "android":
            report.ca_count, report.user_ca_count = \
                self._count_android_certs()
            if report.user_ca_count > 0:
                report.findings.append(
                    f"{report.user_ca_count} user-installed CAs — "
                    "MITM possible if any are malicious")

        # Linux: check /etc/ssl/certs
        elif self._platform == "linux":
            try:
                cert_dir = Path("/etc/ssl/certs")
                if cert_dir.exists():
                    report.ca_count = len(list(cert_dir.glob("*.pem")) +
                                          list(cert_dir.glob("*.crt")))
            except Exception:
                pass

        # System minimum TLS
        try:
            ctx2 = ssl.create_default_context()
            report.system_tls_min = str(ctx2.minimum_version).replace(
                "TLSVersion.", "")
        except Exception:
            pass

        # Findings
        if not report.supports_tls13:
            report.findings.append("TLS 1.3 not supported by Python SSL")
        if report.user_ca_count > 0:
            report.risk_level = "HIGH"
        elif report.ca_count > 200:
            report.findings.append(
                f"Large CA store ({report.ca_count} CAs) — "
                "broad trust surface")
            report.risk_level = "LOW"
        else:
            report.risk_level = "SAFE"

        return report

    def _count_android_certs(self) -> tuple[int, int]:
        system_certs = 0
        user_certs   = 0
        for path, is_user in [
            ("/system/etc/security/cacerts", False),
            ("/data/misc/user/0/cacerts-added", True),
            ("/data/misc/keystore/user_0", True),
        ]:
            try:
                files = os.listdir(path)
                n = len([f for f in files if f.endswith((".pem",".0",""))])
                if is_user:
                    user_certs += n
                else:
                    system_certs += n
            except Exception:
                pass
        return system_certs, user_certs

    @staticmethod
    def _detect_platform() -> str:
        if os.path.exists("/data/data/com.termux"):
            return "android"
        import platform
        return "windows" if "windows" in platform.system().lower() else "linux"


# ─────────────────────────────────────────────────────────────────────────────
# CLI runners
# ─────────────────────────────────────────────────────────────────────────────

def run_ssl_apk_scan_cli(apk_path: str) -> APKSSLReport:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        console = Console()
    except ImportError:
        a = SSLTLSAnalyzer()
        r = a.scan_apk(apk_path)
        for h in r.bypass_hits:
            print(f"[{h.severity}] {h.description}")
        return r

    console.print(f"\n[dim]Scanning SSL/TLS security in {apk_path}...[/dim]")
    analyzer = SSLTLSAnalyzer()
    report   = analyzer.scan_apk(apk_path)

    if report.error:
        console.print(f"[red]Error: {report.error}[/red]")
        return report

    rc = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}.get(
        report.risk_level, "white")

    console.print(Panel(
        f"[bold]Package   :[/bold] {report.package_name or '(unknown)'}\n"
        f"[bold]Cleartext :[/bold] {'[red]Allowed[/red]' if report.uses_cleartext else '[green]Blocked[/green]'}\n"
        f"[bold]Bypasses  :[/bold] "
        f"[red]{report.critical_count} critical[/red]  "
        f"[orange1]{report.high_count} high[/orange1]  "
        f"[yellow]{report.medium_count} medium[/yellow]\n"
        f"[bold]Risk      :[/bold] [{rc}]{report.risk_level}[/{rc}] "
        f"(score={report.risk_score})",
        title="SSL/TLS APK Analysis",
        border_style=rc,
    ))

    if report.bypass_hits:
        t = Table(title="SSL Security Issues", show_lines=True)
        t.add_column("Severity", width=10)
        t.add_column("Location", width=12, style="dim")
        t.add_column("Description")
        sev_style = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"dim"}
        for h in report.bypass_hits[:15]:
            s = sev_style.get(h.severity, "")
            t.add_row(f"[{s}]{h.severity}[/{s}]",
                      h.location, h.description)
        console.print(t)

    return report


def run_ssl_live_scan_cli(domains: list = None) -> LiveSSLReport:
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
    except ImportError:
        a = SSLTLSAnalyzer()
        r = a.scan_live_connections(domains)
        for c in r.certificates:
            print(f"{c.domain}: {c.tls_version} {c.cipher_suite[:30]} "
                  f"expires_in={c.days_remaining}d risk={c.risk}")
        return r

    console.print("\n[dim]Testing live HTTPS connections...[/dim]")
    analyzer = SSLTLSAnalyzer()
    report   = analyzer.scan_live_connections(domains)

    t = Table(title="Live TLS Certificate Check", show_lines=True)
    t.add_column("Domain",     style="cyan")
    t.add_column("TLS",        width=8)
    t.add_column("Cipher",     width=28, style="dim")
    t.add_column("Expires in", width=11)
    t.add_column("Risk",       width=10)
    t.add_column("Issue")

    for c in report.certificates:
        if c.error:
            t.add_row(c.domain, "—", "—", "—", "[dim]error[/dim]", c.error[:35])
            continue
        tls_c = "[red]" if c.has_weak_tls else "[green]"
        tls_e = f"{tls_c}{c.tls_version or '?'}[/{tls_c.strip('<')}]"
        exp_c = "[red]" if c.is_expired else \
                "[yellow]" if c.days_remaining < 30 else "[green]"
        exp_str = f"{exp_c}{c.days_remaining}d[/{exp_c.strip('<')}]"
        rc = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow",
              "LOW":"cyan","OK":"green"}.get(c.risk,"white")
        issues = []
        if c.is_expired:    issues.append("EXPIRED")
        if c.is_self_signed:issues.append("self-signed")
        if c.has_weak_tls:  issues.append(f"weak TLS ({c.tls_version})")
        if c.has_weak_cipher:issues.append("weak cipher")
        t.add_row(c.domain, tls_e, c.cipher_suite[:27], exp_str,
                  f"[{rc}]{c.risk}[/{rc}]",
                  ", ".join(issues) or "[green]✓[/green]")
    console.print(t)
    return report