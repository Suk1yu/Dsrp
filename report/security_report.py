"""
report/security_report.py

Automatic security report generator.
Aggregates data from all ASRP modules into a structured report.

Output formats:
  - JSON (machine-readable, for integrations)
  - Text (human-readable, for Termux display)
  - Markdown (for sharing)

Reports are saved to reports/ directory automatically.
CPU cost: On-demand, runs once — not continuous.
"""

import json
import time
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPORTS_DIR = Path(__file__).parent.parent / "data" / "reports"


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

@dataclass
class ThreatSummary:
    window_hours: float = 24.0
    total_incidents: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    blocks_executed: int = 0
    apps_flagged: int = 0


@dataclass
class NetworkSummary:
    total_connections: int = 0
    unique_domains: int = 0
    tracker_domains: int = 0
    tracker_ratio: float = 0.0
    malicious_ips: int = 0
    c2_candidates: int = 0
    top_domains: list = field(default_factory=list)
    top_tracker_names: list = field(default_factory=list)
    blocked_domains: list = field(default_factory=list)


@dataclass
class AppSummary:
    apps_scanned: int = 0
    high_risk_count: int = 0
    flagged_apps: list = field(default_factory=list)
    top_dangerous_permissions: list = field(default_factory=list)
    tracker_sdks_found: list = field(default_factory=list)


@dataclass
class DefenseSummary:
    mode: str = "MONITOR"
    total_blocked: int = 0
    domains_blocked: int = 0
    ips_blocked: int = 0
    hardening_applied: bool = False
    hardened_packages: list = field(default_factory=list)


@dataclass
class SecurityReport:
    report_id: str
    generated_at: float
    window_hours: float
    device_id: str = "android_device"

    threat: ThreatSummary = field(default_factory=ThreatSummary)
    network: NetworkSummary = field(default_factory=NetworkSummary)
    apps: AppSummary = field(default_factory=AppSummary)
    defense: DefenseSummary = field(default_factory=DefenseSummary)

    ids_alerts: list = field(default_factory=list)
    anomaly_alerts: list = field(default_factory=list)
    top_incidents: list = field(default_factory=list)

    risk_score: int = 0
    risk_level: str = "LOW"
    recommendations: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

class SecurityReportGenerator:
    """
    Collects data from all ASRP modules and builds a SecurityReport.
    All parameters are optional — pass what's available.
    """

    def __init__(self, reports_dir: str = None):
        self.reports_dir = Path(reports_dir or REPORTS_DIR)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._last_report = None   # cached for dashboard Save buttons

    def generate(self,
                 window_hours: float = 24.0,
                 response_engine=None,
                 ids_engine=None,
                 anomaly_detector=None,
                 connection_analyser=None,
                 blocker=None,
                 hardener=None,
                 behavior_model=None,
                 reputation_cache=None) -> SecurityReport:
        """Build a complete security report from available modules."""
        now  = time.time()
        rid  = time.strftime("DSRP-%Y%m%d-%H%M%S")
        report = SecurityReport(
            report_id=rid,
            generated_at=now,
            window_hours=window_hours,
        )

        # --- Threat summary ---
        if response_engine:
            metrics = response_engine.get_metrics()
            status  = response_engine.get_status()
            report.threat.total_incidents  = metrics.get("incidents_total", 0)
            report.threat.blocks_executed  = metrics.get("blocks_executed", 0)
            report.threat.apps_flagged     = metrics.get("apps_flagged", 0)

            incidents = response_engine.get_recent_incidents(n=100)
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                count = sum(1 for i in incidents if i.severity == sev)
                setattr(report.threat, f"{sev.lower()}_count", count)

            report.top_incidents = [i.to_dict() for i in incidents[-20:]]
            report.apps.flagged_apps = list(response_engine.get_flagged_apps().keys())

        # --- IDS alerts ---
        if ids_engine:
            ids_stats = ids_engine.get_stats()
            by_sev = ids_stats.get("by_severity", {})
            report.threat.critical_count = max(
                report.threat.critical_count,
                by_sev.get("CRITICAL", 0))
            report.threat.high_count = max(
                report.threat.high_count,
                by_sev.get("HIGH", 0))
            alerts = ids_engine.get_latest_alerts(n=30)
            report.ids_alerts = [a.to_dict() for a in alerts]

        # --- Anomaly alerts ---
        if anomaly_detector:
            anoms = anomaly_detector.get_alerts(limit=20, min_severity="MEDIUM")
            report.anomaly_alerts = [a.to_dict() for a in anoms]

        # --- Network summary ---
        if connection_analyser:
            ca_report = connection_analyser.analyse(window_secs=window_hours * 3600)
            report.network.total_connections = ca_report.total_connections
            report.network.unique_domains = ca_report.unique_domains
            report.network.tracker_domains = ca_report.tracker_domains
            total = max(ca_report.total_connections, 1)
            report.network.tracker_ratio = round(
                ca_report.tracker_domains / total, 4)
            report.network.top_domains = [
                d["domain"] for d in ca_report.top_domains[:10]
            ]
            report.network.top_tracker_names = [
                t["name"] for t in ca_report.tracker_list[:8]
            ]
            report.network.c2_candidates = len(ca_report.c2_candidates)

        # --- Reputation / malicious IPs ---
        if reputation_cache:
            malicious = reputation_cache.get_malicious(limit=20)
            report.network.malicious_ips = len(
                [e for e in malicious if e.ioc_type == "ip"])

        # --- Defense summary ---
        if blocker:
            bstats = blocker.get_stats()
            report.defense.total_blocked   = bstats.get("total_blocked", 0)
            report.defense.domains_blocked = bstats.get("domains_blocked", 0)
            report.defense.ips_blocked     = bstats.get("ips_blocked", 0)
            blocked = blocker.get_blocked_domains(limit=20)
            report.network.blocked_domains = [e.ioc for e in blocked[:10]]

        if hardener:
            hardened = hardener.get_hardened_packages()
            report.defense.hardening_applied = bool(hardened)
            report.defense.hardened_packages = list(hardened)

        if response_engine:
            report.defense.mode = response_engine.get_status().get("mode", "MONITOR")

        # --- Risk scoring ---
        report.risk_score, report.risk_level = self._score(report)
        report.recommendations = self._recommend(report)

        return report

    def save(self, report: SecurityReport,
             formats: list = None) -> dict:
        """Save report to disk. Returns dict of {format: path}."""
        formats = formats or ["json", "txt"]
        self._last_report = report   # cache for dashboard save buttons
        saved = {}

        if "json" in formats:
            path = self.reports_dir / f"{report.report_id}.json"
            with open(path, "w") as f:
                json.dump(self._to_dict(report), f, indent=2)
            saved["json"] = str(path)

        if "txt" in formats:
            path = self.reports_dir / f"{report.report_id}.txt"
            with open(path, "w") as f:
                f.write(self.render_text(report))
            saved["txt"] = str(path)

        if "md" in formats:
            path = self.reports_dir / f"{report.report_id}.md"
            with open(path, "w") as f:
                f.write(self.render_markdown(report))
            saved["md"] = str(path)

        return saved

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render_text(self, report: SecurityReport) -> str:
        lines = [
            "=" * 60,
            "  DSRP Device Security Report",
            "=" * 60,
            f"  Report ID : {report.report_id}",
            f"  Generated : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.generated_at))}",
            f"  Window    : {report.window_hours:.0f} hours",
            f"  Risk Level: {report.risk_level} (score={report.risk_score})",
            "",
            "── THREAT SUMMARY ──────────────────────────────────",
            f"  Total Incidents : {report.threat.total_incidents}",
            f"  Critical        : {report.threat.critical_count}",
            f"  High            : {report.threat.high_count}",
            f"  Medium          : {report.threat.medium_count}",
            f"  Blocks Executed : {report.threat.blocks_executed}",
            f"  Apps Flagged    : {report.threat.apps_flagged}",
            "",
            "── NETWORK SUMMARY ─────────────────────────────────",
            f"  Connections     : {report.network.total_connections}",
            f"  Unique Domains  : {report.network.unique_domains}",
            f"  Tracker Domains : {report.network.tracker_domains}",
            f"  Tracker Ratio   : {report.network.tracker_ratio:.1%}",
            f"  Malicious IPs   : {report.network.malicious_ips}",
            f"  C2 Candidates   : {report.network.c2_candidates}",
            "",
        ]

        if report.network.top_domains:
            lines.append("  Top Domains:")
            for d in report.network.top_domains[:8]:
                lines.append(f"    • {d}")
            lines.append("")

        if report.network.top_tracker_names:
            lines.append("  Active Trackers:")
            for t in report.network.top_tracker_names[:6]:
                lines.append(f"    • {t}")
            lines.append("")

        lines += [
            "── DEFENSE STATUS ──────────────────────────────────",
            f"  Mode            : {report.defense.mode}",
            f"  Domains Blocked : {report.defense.domains_blocked}",
            f"  IPs Blocked     : {report.defense.ips_blocked}",
            f"  Hardening       : {'Applied' if report.defense.hardening_applied else 'Not applied'}",
            "",
        ]

        if report.apps.flagged_apps:
            lines.append("  Flagged Apps:")
            for app in report.apps.flagged_apps[:5]:
                lines.append(f"    ⚠ {app}")
            lines.append("")

        if report.recommendations:
            lines.append("── RECOMMENDATIONS ─────────────────────────────────")
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")

        if report.network.blocked_domains:
            lines.append("── BLOCKED DOMAINS (recent) ────────────────────────")
            for d in report.network.blocked_domains[:8]:
                lines.append(f"    ✗ {d}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def render_markdown(self, report: SecurityReport) -> str:
        ts = time.strftime('%Y-%m-%d %H:%M:%S',
                           time.localtime(report.generated_at))
        lines = [
            f"# DSRP Device Security Report",
            f"",
            f"**Report ID:** `{report.report_id}`  ",
            f"**Generated:** {ts}  ",
            f"**Window:** {report.window_hours:.0f} hours  ",
            f"**Risk Level:** `{report.risk_level}` (score: {report.risk_score})",
            f"",
            f"## Threat Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Incidents | {report.threat.total_incidents} |",
            f"| Critical | 🔴 {report.threat.critical_count} |",
            f"| High | 🟠 {report.threat.high_count} |",
            f"| Medium | 🟡 {report.threat.medium_count} |",
            f"| Blocks Executed | {report.threat.blocks_executed} |",
            f"| Apps Flagged | {report.threat.apps_flagged} |",
            f"",
            f"## Network Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Connections | {report.network.total_connections} |",
            f"| Unique Domains | {report.network.unique_domains} |",
            f"| Tracker Domains | {report.network.tracker_domains} |",
            f"| Tracker Ratio | {report.network.tracker_ratio:.1%} |",
            f"| C2 Candidates | {report.network.c2_candidates} |",
            f"",
        ]

        if report.network.top_tracker_names:
            lines += ["## Active Trackers", ""]
            for t in report.network.top_tracker_names[:8]:
                lines.append(f"- {t}")
            lines.append("")

        if report.recommendations:
            lines += ["## Recommendations", ""]
            for rec in report.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        return "\n".join(lines)

    def get_latest_report(self) -> Optional[str]:
        """Return path of most recent report JSON."""
        reports = sorted(self.reports_dir.glob("*.json"), reverse=True)
        return str(reports[0]) if reports else None

    def list_reports(self) -> list[dict]:
        """List saved reports sorted by newest first."""
        reports = []
        for p in sorted(self.reports_dir.glob("report_*.json"),
                        key=lambda x: x.stat().st_mtime, reverse=True)[:20]:
            try:
                with open(p) as f:
                    d = json.load(f)
                import time as _time
                ts = d.get("generated_at", 0)
                date_str = _time.strftime("%Y-%m-%d %H:%M",
                                          _time.localtime(ts)) if ts else "?"
                reports.append({
                    "path":        str(p),
                    "id":          d.get("report_id", p.stem)[:16],
                    "date":        date_str,
                    "generated_at":ts,
                    "risk_level":  d.get("risk_level", "?"),
                    "risk_score":  d.get("risk_score", 0),
                    "filename":    p.name,
                })
            except Exception:
                pass
        return reports

    def delete_reports(self, latest_only: bool = True) -> int:
        """
        Delete saved reports.
        latest_only=True  → delete the most recently saved report only.
        latest_only=False → delete ALL report files in reports_dir.
        Returns number of files deleted.
        """
        deleted = 0
        try:
            if latest_only:
                files = sorted(
                    self.reports_dir.glob("report_*"),
                    key=lambda x: x.stat().st_mtime, reverse=True)
                if files:
                    # Delete all format variants of the latest report
                    latest_stem = files[0].stem
                    for ext in (".json", ".txt", ".md"):
                        candidate = self.reports_dir / (latest_stem + ext)
                        if candidate.exists():
                            candidate.unlink()
                            deleted += 1
            else:
                for f in self.reports_dir.glob("report_*"):
                    try:
                        f.unlink()
                        deleted += 1
                    except Exception:
                        pass
        except Exception:
            pass
        return deleted

    # ------------------------------------------------------------------
    # Scoring and recommendations
    # ------------------------------------------------------------------

    def _score(self, report: SecurityReport) -> tuple[int, str]:
        score = 0
        score += report.threat.critical_count * 15
        score += report.threat.high_count * 8
        score += report.threat.medium_count * 3
        score += report.network.malicious_ips * 20
        score += report.network.c2_candidates * 12
        score += min(report.network.tracker_domains * 2, 20)
        score += len(report.apps.flagged_apps) * 10

        if score >= 60:
            level = "CRITICAL"
        elif score >= 30:
            level = "HIGH"
        elif score >= 10:
            level = "MEDIUM"
        else:
            level = "LOW"

        return score, level

    def _recommend(self, report: SecurityReport) -> list[str]:
        recs = []
        if report.threat.critical_count > 0:
            recs.append("Investigate CRITICAL incidents immediately — "
                        "possible active compromise")
        if report.network.c2_candidates > 0:
            recs.append(f"Review {report.network.c2_candidates} C2 beaconing "
                        "candidates in connection analysis")
        if report.network.malicious_ips > 0:
            recs.append(f"Block or investigate {report.network.malicious_ips} "
                        "malicious IPs in reputation cache")
        if report.apps.flagged_apps:
            recs.append(f"Review or uninstall flagged apps: "
                        f"{', '.join(report.apps.flagged_apps[:3])}")
        if report.network.tracker_ratio > 0.3:
            recs.append("High tracker traffic ratio — consider enabling "
                        "DEFENSIVE or STRICT mode")
        if not report.defense.hardening_applied:
            recs.append("Run Privacy Hardening (SAFE level) to disable "
                        "unnecessary telemetry services")
        if report.defense.mode == "MONITOR":
            recs.append("Switch to DEFENSIVE mode to automatically block "
                        "tracker and malicious domains")
        if not recs:
            recs.append("System appears healthy. Continue monitoring.")
        return recs[:6]

    def _to_dict(self, report: SecurityReport) -> dict:
        """Convert SecurityReport to JSON-serialisable dict."""
        def _convert(obj):
            if hasattr(obj, "__dataclass_fields__"):
                return {k: _convert(v)
                        for k, v in vars(obj).items()}
            if isinstance(obj, list):
                return [_convert(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _convert(v) for k, v in obj.items()}
            return obj
        return _convert(report)
