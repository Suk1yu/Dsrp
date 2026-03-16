"""
core_engine.py

DSRPCore — Central orchestrator for all 5 stages.
Manages module lifecycle, data collection, and the shared data dict
that feeds the Textual dashboard.

Lifecycle:
  core = DSRPCore()
  core.start_all()           # starts all background threads
  data = core.collect_data() # snapshot for dashboard
  core.stop_all()            # clean shutdown

All module failures are caught silently — partial functionality
is always better than a crash.
"""

import time
import threading
import traceback
from pathlib import Path
from typing import Optional

from config import cfg
from logger import get_logger, DSRPLogger
from resource_limiter import limiter, ResourceLevel

log = get_logger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# DSRPCore
# ─────────────────────────────────────────────────────────────────────────────

class DSRPCore:
    """
    Central orchestrator. Holds references to all Stage 1–5 modules.
    Thread-safe data collection via collect_data().
    """

    def __init__(self,
                 defense_mode: str = None,
                 enable_remote_intel: bool = None,
                 scan_interval_wifi: float = None,
                 poll_interval_network: float = None):

        # Resolve from config when not explicitly overridden
        self._defense_mode_str = (
            defense_mode or cfg.general.defense_mode).upper()
        self._enable_remote = (
            enable_remote_intel
            if enable_remote_intel is not None
            else cfg.general.enable_remote_intel)

        log.info("DSRPCore init  mode=%s  remote_intel=%s",
                 self._defense_mode_str, self._enable_remote)

        # Module references (all optional — None until started)
        self.ct     = None   # ConnectionTracker (Stage 2)
        self.dns    = None   # DNSMonitor (Stage 2)
        self.meta   = None   # PacketMetadataCollector (Stage 2)
        self.mapper = None   # NetworkMapper (Stage 2)
        self.ids    = None   # IDSEngine (Stage 3)
        self.anomaly = None  # TrafficAnomalyDetector (Stage 3)
        self.fw     = None   # TrafficFeatureWindow (Stage 3)
        self.behavior = None # MalwareBehaviorModel (Stage 3)
        self.policy = None   # PolicyEngine (Stage 5)
        self.blocker = None  # AutoBlocker (Stage 5)
        self.response = None # ResponseEngine (Stage 5)
        self.hardener = None # PrivacyHardener (Stage 5)
        self.logger = None   # IncidentLogger (Stage 5)
        self.rep_cache = None # ReputationCache (Stage 3/4)
        self.report_gen = None # SecurityReportGenerator (Stage 5)
        self.ca     = None   # ConnectionAnalyser (Stage 4)
        self.ioc_updater = None # IOCUpdater (Stage 4)
        self.tracker_db: dict = {}

        self._running = False
        self._lock = threading.Lock()
        self._last_data: dict = {}

        # Track last app scan results
        self._ml_predictions: list = []
        self._apps_scanned: int = 0

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def start_all(self):
        """Start all modules. Failures are isolated."""
        self._running = True
        self._init_tracker_db()
        self._init_stage5()
        self._init_stage3()
        self._init_stage2()
        self._init_stage4()

    def stop_all(self):
        self._running = False
        for attr in ("ct", "dns", "meta", "mapper", "anomaly", "ioc_updater"):
            m = getattr(self, attr, None)
            if m:
                try:
                    m.stop()
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # Module initialisation
    # ─────────────────────────────────────────────────────────────────────────

    def _init_tracker_db(self):
        try:
            from network.tracker_detector import TrackerDetector
            db_path = Path(__file__).parent / "data" / "tracker_domains.json"
            det = TrackerDetector(str(db_path) if db_path.exists() else None)
            self.tracker_db = det.build_flat_dict()
        except Exception:
            self.tracker_db = {}

    def _init_stage2(self):
        """Stage 2: DNS monitor, connection tracker, metadata, WiFi mapper."""
        try:
            from network.connection_tracker import ConnectionTracker
            self.ct = ConnectionTracker(
                poll_interval=cfg.network.connection_poll_interval,
                tracker_db=self.tracker_db)
            self.ct.start()
            log.info("ConnectionTracker started")
        except Exception as e:
            log.warning("ConnectionTracker unavailable: %s", e)

        try:
            from network.dns_monitor import DNSMonitor
            self.dns = DNSMonitor(
                poll_interval=cfg.network.dns_poll_interval,
                tracker_db=self.tracker_db)

            def on_dns(record):
                if self.blocker and self.blocker.is_blocked(record.domain):
                    log.debug("DNS blocked: %s", record.domain)
                    return
                if record.is_tracker and self.response:
                    self.response.on_tracker_domain(
                        record.domain, record.tracker_name)
                if self.rep_cache:
                    self.rep_cache.enqueue_lookup(record.domain)

            self.dns.add_callback(on_dns)
            self.dns.start()
            log.info("DNSMonitor started")
        except Exception as e:
            log.warning("DNSMonitor unavailable: %s", e)

        try:
            from network.packet_metadata import PacketMetadataCollector
            self.meta = PacketMetadataCollector(
                poll_interval=cfg.network.connection_poll_interval)

            def on_conns(conns):
                if not limiter.ok_to_run("connection_poll"):
                    return
                for c in conns:
                    if self.fw:
                        self.fw.add_from_connection(c)
                    if self.ids:
                        alerts = self.ids.process_connection(c)
                        for a in alerts:
                            log.info("IDS alert  rule=%s  severity=%s  %s",
                                     a.rule_id, a.severity, a.description[:60])
                            if self.response:
                                self.response.on_ids_alert(a)
                            if self.logger:
                                self.logger.log_raw(
                                    severity=a.severity, source="IDS",
                                    description=a.description,
                                    ioc=a.evidence.get("dst_ip",""),
                                )

            self.meta.add_callback(on_conns)
            self.meta.start()
            log.info("PacketMetadataCollector started")
        except Exception as e:
            log.warning("PacketMetadataCollector unavailable: %s", e)

        try:
            from network.network_mapper import NetworkMapper
            self.mapper = NetworkMapper(
                scan_interval=cfg.network.wifi_scan_interval)
            self.mapper.start_periodic()
            log.info("NetworkMapper started  interval=%ds",
                     cfg.network.wifi_scan_interval)
        except Exception as e:
            log.warning("NetworkMapper unavailable: %s", e)

    def _init_stage3(self):
        """Stage 3: IDS, AI anomaly, malware behavior model, reputation."""
        try:
            from network.traffic_features import TrafficFeatureWindow
            self.fw = TrafficFeatureWindow(window_secs=30.0)
        except Exception:
            pass

        try:
            from ai.traffic_anomaly import TrafficAnomalyDetector
            if self.fw:
                self.anomaly = TrafficAnomalyDetector(
                    feature_window=self.fw, analysis_interval=15.0)

                def on_anomaly(alert):
                    if self.response:
                        self.response.on_anomaly_alert(alert)
                    if self.logger:
                        self.logger.log_raw(
                            severity=alert.severity,
                            source="ANOMALY",
                            description=alert.description,
                        )

                self.anomaly.add_callback(on_anomaly)
                self.anomaly.start()
        except Exception:
            pass

        try:
            from ids.ids_engine import IDSEngine
            self.ids = IDSEngine(log_to_file=True)
        except Exception:
            pass

        try:
            from ai.malware_behavior_model import MalwareBehaviorModel
            self.behavior = MalwareBehaviorModel(use_rf=True, auto_train=True)
        except Exception:
            pass

        try:
            from intel.reputation_cache import ReputationCache
            self.rep_cache = ReputationCache(
                enable_remote=self._enable_remote)

            def on_rep_hit(entry):
                if entry.is_malicious and self.response:
                    self.response.on_reputation_hit(entry)

            self.rep_cache.add_callback(on_rep_hit)
        except Exception:
            pass

    def _init_stage4(self):
        """Stage 4: Connection analyser, IOC updater."""
        try:
            from analysis.connection_analysis import ConnectionAnalyser
            self.ca = ConnectionAnalyser(window_secs=300.0)
        except Exception:
            pass

        try:
            from intel.ioc_updater import IOCUpdater
            self.ioc_updater = IOCUpdater()
            self.ioc_updater.start_auto_update()
        except Exception:
            pass

    def _init_stage5(self):
        """Stage 5: Policy engine, blocker, response engine, logger, hardener."""
        try:
            from defense.policy_engine import PolicyEngine, PolicyMode
            mode = PolicyMode[self._defense_mode_str.upper()]
            self.policy = PolicyEngine(mode=mode)
        except Exception:
            pass

        try:
            from defense.auto_blocker import AutoBlocker
            self.blocker = AutoBlocker()
        except Exception:
            pass

        try:
            from defense.response_engine import ResponseEngine
            if self.policy and self.blocker:
                self.response = ResponseEngine(
                    policy=self.policy, blocker=self.blocker)
        except Exception:
            pass

        try:
            from defense.privacy_hardener import PrivacyHardener
            self.hardener = PrivacyHardener()
        except Exception:
            pass

        try:
            from report.incident_logger import IncidentLogger
            self.logger = IncidentLogger()
        except Exception:
            pass

        try:
            from report.security_report import SecurityReportGenerator
            self.report_gen = SecurityReportGenerator()
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Data collection — called by dashboard every 3 seconds
    # ─────────────────────────────────────────────────────────────────────────

    def collect_data(self) -> dict:
        """Snapshot all module state into a flat dict for the dashboard."""
        data = dict(self._last_data)  # start from last known good

        # ── Resource Governor ─────────────────────────────────────────
        try:
            res_stats = limiter.get_stats()
            data["resource_level"]   = res_stats.get("level", "NORMAL")
            data["resource_cpu"]     = res_stats.get("cpu_percent", 0)
            data["resource_ram_mb"]  = res_stats.get("ram_used_mb", 0)
            data["resource_skipped"] = res_stats.get("tasks_skipped", 0)
        except Exception:
            pass

        # ── System Stats (/proc fallback — works without psutil) ─────
        try:
            from system.proc_stats import get_stats_reader
            sys_stats = get_stats_reader().get()
            data["cpu"]      = sys_stats.cpu_percent
            data["ram_mb"]   = sys_stats.ram_used_mb
            data["ram_total_mb"] = sys_stats.ram_total_mb
            data["ram_pct"]  = sys_stats.ram_percent
            data["net_up"]   = sys_stats.net_sent_rate
            data["net_down"] = sys_stats.net_recv_rate
            data["battery"]  = sys_stats.battery_percent
        except Exception:
            pass

        # ── Stage 2: Connections ──────────────────────────────────────
        if self.ct:
            try:
                conns = self.ct.get_active_connections()
                data["connections"] = [
                    {
                        "process_name": c.process_name,
                        "remote_ip": c.remote_ip,
                        "remote_hostname": c.remote_hostname,
                        "remote_port": c.remote_port,
                        "protocol": c.protocol,
                        "is_tracker": c.is_tracker,
                        "is_suspicious": c.is_suspicious,
                        "tracker_name": c.tracker_name,
                    }
                    for c in conns[:20]
                ]
                tracker_conns = self.ct.get_tracker_connections()
                data["tracker_count"] = len(tracker_conns)
                ct_stats = self.ct.get_stats()
                data["connection_tree"] = self.ct.get_ascii_tree(max_apps=15)
            except Exception:
                pass

        if self.dns:
            try:
                domain_stats = self.dns.get_domain_stats(top=20)
                data["top_domains"] = [
                    {
                        "domain": s.domain,
                        "count": s.request_count,
                        "is_tracker": s.is_tracker,
                        "tracker_name": s.tracker_name,
                    }
                    for s in domain_stats
                ]
                tracker_alerts = self.dns.get_tracker_alerts(limit=10)
                data["tracker_domains"] = [
                    {"domain": s.domain, "tracker_name": s.tracker_name,
                     "count": s.request_count}
                    for s in tracker_alerts
                ]
            except Exception:
                pass

        if self.mapper:
            try:
                devices = self.mapper.get_devices()
                data["wifi_devices"] = [
                    {"ip": d.ip, "mac": d.mac,
                     "display_name": d.display_name, "vendor": d.vendor}
                    for d in devices
                ]
            except Exception:
                pass

        # ── Stage 3: IDS + Anomaly ─────────────────────────────────────
        if self.ids:
            try:
                ids_stats = self.ids.get_stats()
                data["ids_total"] = ids_stats.get("alerts_generated", 0)
                alerts = self.ids.get_latest_alerts(n=15)
                data["ids_alerts"] = [a.to_dict() for a in alerts]
            except Exception:
                pass

        if self.anomaly:
            try:
                anom_status = self.anomaly.get_status()
                data["anomaly_model_ready"] = anom_status.get("model_trained", False)
                anom_alerts = self.anomaly.get_alerts(limit=10, min_severity="LOW")
                data["anomaly_alerts"] = [a.to_dict() for a in anom_alerts]
                data["anomaly_total"] = len(anom_alerts)
            except Exception:
                pass

        if self.fw:
            try:
                vec = self.fw.extract()
                if vec:
                    from network.traffic_features import FEATURE_NAMES
                    data["traffic_features"] = dict(zip(FEATURE_NAMES, vec))
            except Exception:
                pass

        # ── Stage 4: Analysis + Intel ─────────────────────────────────
        if self.ca and self.ct:
            try:
                self.ca.ingest_connections(self.ct.get_active_connections())
                ca_report = self.ca.analyse(window_secs=300.0)
                data["c2_candidates"] = [
                    {
                        "app": c.app, "remote": c.remote,
                        "interval_mean": c.interval_mean,
                        "confidence": c.confidence,
                    }
                    for c in ca_report.c2_candidates[:8]
                ]
            except Exception:
                pass

        if self.rep_cache:
            try:
                malicious = self.rep_cache.get_malicious(limit=15)
                data["malicious_iocs"] = [
                    {"ioc": e.ioc, "ioc_type": e.ioc_type,
                     "reputation": e.reputation, "score": e.score}
                    for e in malicious
                ]
            except Exception:
                pass

        # ML predictions cache
        data["ml_predictions"] = [
            {
                "package_name": p.package_name,
                "risk_level": p.risk_level,
                "risk_label": p.risk_label,
                "probability_malware": p.probability_malware,
            }
            for p in self._ml_predictions[-10:]
        ]
        data["apps_scanned"] = self._apps_scanned

        # ── Stage 5: Defense ──────────────────────────────────────────
        if self.policy:
            try:
                ps = self.policy.get_mode_summary()
                data["defense_mode"] = ps["mode"]
                data["policy_rules"] = ps["rules"]
            except Exception:
                pass

        if self.blocker:
            try:
                bstats = self.blocker.get_stats()
                data["blocked_total"]   = bstats.get("total_blocked", 0)
                data["blocked_domains"] = bstats.get("domains_blocked", 0)
                data["blocked_ips"]     = bstats.get("ips_blocked", 0)
                blocked = self.blocker.get_blocked_domains(limit=15)
                data["blocklist"] = [
                    {"ioc": e.ioc, "threat_type": e.threat_type,
                     "source": e.source, "reason": e.reason}
                    for e in blocked
                ]
            except Exception:
                pass

        if self.response:
            try:
                metrics = self.response.get_metrics()
                data["incidents_total"] = metrics.get("incidents_total", 0)
                flagged = self.response.get_flagged_apps()
                data["flagged_apps_count"] = len(flagged)
                incidents = self.response.get_recent_incidents(n=20)
                data["recent_incidents"] = [
                    {
                        "incident_id": i.incident_id,
                        "timestamp": i.timestamp,
                        "severity": i.severity,
                        "source": i.source,
                        "description": i.description,
                        "ioc": i.ioc,
                        "app": i.app,
                        "actions_taken": i.actions_taken,
                    }
                    for i in incidents
                ]
            except Exception:
                pass

        if self.hardener:
            try:
                hardened = self.hardener.get_hardened_packages()
                data["hardened_packages"] = list(hardened)
            except Exception:
                pass

        # Debloat list (cached — only updated when scan is triggered)
        if "bloatware_list" not in data:
            data["bloatware_list"] = []

        # Saved reports list
        if self.report_gen:
            try:
                data["saved_reports_list"] = self.report_gen.list_reports()
            except Exception:
                pass
        elif "saved_reports_list" not in data:
            data["saved_reports_list"] = []

        with self._lock:
            self._last_data = data

        return data

    # ─────────────────────────────────────────────────────────────────────────
    # Debloat actions
    # ─────────────────────────────────────────────────────────────────────────

    def run_debloat_scan(self):
        """Cross-platform bloatware scanner."""
        if not limiter.ok_to_run("wifi_scan"):
            log.debug("Debloat scan skipped — resource pressure")
            return
        try:
            from system.debloat_cross import DebloatEngineCross
            log.info("Running cross-platform bloatware scan")
            engine = DebloatEngineCross()
            result = engine.scan()

            bloat_data = [
                {
                    "package":     item.id,
                    "description": item.description,
                    "safe":        item.safe_to_remove,
                    "remove_cmd":  item.remove_command,
                    "category":    item.category,
                }
                for item in result.items
            ]

            with self._lock:
                self._last_data["bloatware_list"] = bloat_data

            log.info("Bloatware scan complete  platform=%s  found=%d",
                     engine.platform, len(bloat_data))
        except Exception as e:
            log.error("Bloatware scan failed: %s", e)

    def run_hardening(self, level: str = "SAFE", dry_run: bool = True):
        """Run privacy hardening at the given level."""
        if not self.hardener:
            return
        try:
            log.info("Running hardening  level=%s  dry_run=%s", level, dry_run)
            report = self.hardener.harden(level=level, dry_run=dry_run)
            log.info("Hardening done  succeeded=%d  failed=%d",
                     report.succeeded, report.failed)
            # Refresh hardened packages in data
            with self._lock:
                self._last_data["hardened_packages"] = \
                    list(self.hardener.get_hardened_packages())
        except Exception as e:
            log.error("Hardening failed: %s", e)

    # ─────────────────────────────────────────────────────────────────────────
    # Actions (called from dashboard buttons / keybindings)
    # ─────────────────────────────────────────────────────────────────────────

    def set_mode(self, mode_str: str):
        """Change defense policy mode."""
        if self.policy:
            try:
                from defense.policy_engine import PolicyMode
                self.policy.set_mode(PolicyMode[mode_str.upper()])
            except Exception:
                pass
        if self.response:
            try:
                from defense.policy_engine import PolicyMode
                self.response.set_mode(PolicyMode[mode_str.upper()])
            except Exception:
                pass

    def block_domain(self, domain: str, reason: str = "manual"):
        if self.blocker:
            self.blocker.block_domain(domain, reason=reason, source="manual")

    def unblock(self, ioc: str):
        if self.blocker:
            self.blocker.unblock(ioc)

    def run_app_scan(self):
        """Scan installed apps and run ML behavior model."""
        if not limiter.ok_to_run("ml_retrain"):
            log.warning("App scan skipped — resource pressure %s", limiter.level.name)
            return
        try:
            from core.app_analyzer import AppAnalyzer
            from ai.malware_behavior_model import AppBehaviorSnapshot

            log.info("Starting app malware scan")
            analyzer = AppAnalyzer()
            packages = analyzer.get_installed_packages()[:40]
            preds = []
            for pkg in packages:
                profile = analyzer.analyze_package(pkg)
                if self.behavior:
                    snap = AppBehaviorSnapshot.from_profile(profile)
                    pred = self.behavior.predict(snap)
                    preds.append(pred)
                    if pred.risk_level in ("HIGH", "CRITICAL"):
                        log.warning("High-risk app  pkg=%s  risk=%s  prob=%.2f",
                                    pkg, pred.risk_level, pred.probability_malware)
                        if self.response:
                            self.response.on_behavior_prediction(pred)
            self._ml_predictions = preds
            self._apps_scanned = len(preds)
            log.info("App scan complete  scanned=%d  high_risk=%d",
                     len(preds),
                     sum(1 for p in preds if p.risk_level in ("HIGH","CRITICAL")))
        except Exception as e:
            log.error("App scan failed: %s", e)

    def run_wifi_scan(self):
        if not limiter.ok_to_run("wifi_scan"):
            log.debug("WiFi scan skipped — resource pressure %s", limiter.level.name)
            return
        if self.mapper:
            try:
                log.info("Starting WiFi scan")
                self.mapper.scan_now()
            except Exception as e:
                log.error("WiFi scan failed: %s", e)

    def rebuild_graph(self):
        """Rebuild the network graph (called on-demand)."""
        if not limiter.ok_to_run("graph_rebuild"):
            log.debug("Graph rebuild skipped — resource pressure")
            return
        try:
            from analysis.network_graph import NetworkGraph
            graph = NetworkGraph()
            if self.ct:
                conns = self.ct.get_active_connections()
                graph.build_from_connections(conns, tracker_db=self.tracker_db)
            elif self.dns:
                stats = self.dns.get_domain_stats(top=40)
                graph.build_from_dns_stats(stats, tracker_db=self.tracker_db)
            with self._lock:
                self._last_data["connection_tree"] = graph.ascii_tree(max_depth=2)
            log.info("Graph rebuilt  nodes=%d", graph.get_stats().get("nodes", 0))
        except Exception as e:
            log.error("Graph rebuild failed: %s", e)

    def generate_report(self):
        """Generate and save a security report."""
        if not limiter.ok_to_run("report_generation"):
            log.warning("Report generation skipped — resource pressure")
            return
        if self.report_gen:
            try:
                log.info("Generating security report")
                report = self.report_gen.generate(
                    window_hours=24.0,
                    response_engine=self.response,
                    ids_engine=self.ids,
                    connection_analyser=self.ca,
                    blocker=self.blocker,
                    hardener=self.hardener,
                    reputation_cache=self.rep_cache,
                )
                saved = self.report_gen.save(report, formats=["json", "txt", "md"])
                with self._lock:
                    self._last_data["report_risk_level"] = report.risk_level
                    self._last_data["report_risk_score"] = report.risk_score
                log.info("Report saved  risk=%s  files=%s",
                         report.risk_level, list(saved.values()))
            except Exception as e:
                log.error("Report generation failed: %s", e)

    def update_ioc_feeds(self):
        if not limiter.ok_to_run("ioc_feed_update"):
            log.debug("IOC feed update skipped — resource pressure")
            return
        if self.ioc_updater:
            try:
                log.info("Updating IOC feeds")
                self.ioc_updater.update_now()
            except Exception as e:
                log.error("IOC feed update failed: %s", e)

    def list_reports(self) -> list:
        if self.report_gen:
            try:
                return self.report_gen.list_reports()
            except Exception:
                pass
        return []