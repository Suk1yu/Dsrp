"""
network/speed_test.py

Internet speed test — no external packages needed.
Uses urllib (stdlib) for download + upload tests.

Tests:
  1. Ping / latency    — TCP connect time to multiple servers
  2. Download speed    — fetch test file from CDN
  3. Upload speed      — POST data to httpbin-style endpoint
  4. DNS resolution time

Servers used (all free, no account needed):
  Download: Cloudflare / fast.com CDN / GitHub releases
  Ping    : 1.1.1.1, 8.8.8.8, google.com
  Upload  : httpbin.org (free, no rate limit for small payloads)
"""

import time
import socket
import threading
import urllib.request
import urllib.error
import ssl
import os
from dataclasses import dataclass, field
from typing import Optional, Callable


# ─────────────────────────────────────────────────────────────────────────────
# Test servers
# ─────────────────────────────────────────────────────────────────────────────

DOWNLOAD_URLS = [
    # 10 MB test file from Cloudflare (very fast, global CDN)
    "https://speed.cloudflare.com/__down?bytes=10000000",
    # 5 MB from GitHub (fallback)
    "https://github.com/nicholasstephan/speed-test/raw/master/10mb.bin",
    # 1 MB from httpbin (small fallback)
    "https://httpbin.org/bytes/1000000",
]

UPLOAD_URL = "https://httpbin.org/post"

PING_HOSTS = [
    ("1.1.1.1",     443,  "Cloudflare"),
    ("8.8.8.8",     443,  "Google DNS"),
    ("8.8.4.4",     443,  "Google DNS 2"),
    ("9.9.9.9",     443,  "Quad9"),
    ("208.67.222.222", 443, "OpenDNS"),
]

DNS_TEST_DOMAINS = [
    "google.com",
    "cloudflare.com",
    "amazon.com",
]


# ─────────────────────────────────────────────────────────────────────────────
# Results
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PingResult:
    host: str
    label: str
    latency_ms: float       # -1 if unreachable
    reachable: bool

    @property
    def display(self) -> str:
        if not self.reachable:
            return f"{self.host} ({self.label}): UNREACHABLE"
        return f"{self.host} ({self.label}): {self.latency_ms:.1f} ms"


@dataclass
class SpeedTestResult:
    # Ping
    ping_results: list = field(default_factory=list)
    best_ping_ms: float = -1.0
    avg_ping_ms: float  = -1.0

    # Download
    download_mbps: float = 0.0
    download_mb:   float = 0.0
    download_secs: float = 0.0
    download_server: str = ""
    download_error: str  = ""

    # Upload
    upload_mbps: float = 0.0
    upload_mb:   float = 0.0
    upload_secs: float = 0.0
    upload_error: str  = ""

    # DNS
    dns_avg_ms: float = 0.0
    dns_results: list = field(default_factory=list)

    # Meta
    timestamp: float = field(default_factory=time.time)
    duration_secs: float = 0.0
    isp_ip: str = ""

    @property
    def quality(self) -> str:
        """Simple quality rating based on download speed."""
        if self.download_mbps >= 100:  return "Excellent"
        if self.download_mbps >= 25:   return "Good"
        if self.download_mbps >= 10:   return "Fair"
        if self.download_mbps >= 1:    return "Slow"
        if self.download_mbps > 0:     return "Very Slow"
        return "No connection"

    @property
    def quality_color(self) -> str:
        colors = {
            "Excellent":   "#3FB950",
            "Good":        "#3FB950",
            "Fair":        "#F0B429",
            "Slow":        "#FF7B72",
            "Very Slow":   "#FF7B72",
            "No connection": "#6E7681",
        }
        return colors.get(self.quality, "#C9D1D9")

    def summary(self) -> str:
        lines = [
            f"Download : {self.download_mbps:.2f} Mbps",
            f"Upload   : {self.upload_mbps:.2f} Mbps",
            f"Ping     : {self.best_ping_ms:.1f} ms (best)",
            f"DNS      : {self.dns_avg_ms:.1f} ms (avg)",
            f"Quality  : {self.quality}",
        ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Speed test engine
# ─────────────────────────────────────────────────────────────────────────────

class SpeedTest:
    """
    Internet speed test using stdlib only.
    No pip install required.

    Usage:
        st = SpeedTest()
        result = st.run()   # runs all tests
        print(result.summary())

    Or run individual tests:
        ping = st.run_ping()
        dl   = st.run_download()
        ul   = st.run_upload()
        dns  = st.run_dns()
    """

    DOWNLOAD_TIMEOUT  = 20    # seconds
    UPLOAD_TIMEOUT    = 15
    PING_TIMEOUT      = 3
    UPLOAD_SIZE_MB    = 2     # MB to upload
    DOWNLOAD_CHUNK    = 65536 # bytes per read

    def __init__(self,
                 progress_callback: Optional[Callable] = None):
        """
        progress_callback(stage: str, percent: float, message: str)
        stage: "ping" | "dns" | "download" | "upload" | "done"
        """
        self._progress = progress_callback
        self._ctx = ssl.create_default_context()
        # Allow slightly older TLS for compatibility
        self._ctx.check_hostname = False
        self._ctx.verify_mode    = ssl.CERT_NONE

    # ------------------------------------------------------------------
    # Full test
    # ------------------------------------------------------------------

    def run(self, run_upload: bool = True) -> SpeedTestResult:
        result = SpeedTestResult()
        t0 = time.time()

        self._emit("start", 0, "Starting speed test...")

        # 1. Public IP
        result.isp_ip = self._get_public_ip()

        # 2. Ping
        self._emit("ping", 5, "Testing latency...")
        pings = self.run_ping()
        result.ping_results = pings
        reachable_pings = [p.latency_ms for p in pings if p.reachable]
        if reachable_pings:
            result.best_ping_ms = min(reachable_pings)
            result.avg_ping_ms  = sum(reachable_pings) / len(reachable_pings)

        # 3. DNS
        self._emit("dns", 20, "Testing DNS resolution...")
        dns_results, dns_avg = self.run_dns()
        result.dns_results = dns_results
        result.dns_avg_ms  = dns_avg

        # 4. Download
        self._emit("download", 35, "Testing download speed...")
        dl = self.run_download()
        result.download_mbps   = dl.get("mbps", 0)
        result.download_mb     = dl.get("mb", 0)
        result.download_secs   = dl.get("secs", 0)
        result.download_server = dl.get("server", "")
        result.download_error  = dl.get("error", "")

        # 5. Upload
        if run_upload:
            self._emit("upload", 75, "Testing upload speed...")
            ul = self.run_upload()
            result.upload_mbps  = ul.get("mbps", 0)
            result.upload_mb    = ul.get("mb", 0)
            result.upload_secs  = ul.get("secs", 0)
            result.upload_error = ul.get("error", "")

        result.duration_secs = round(time.time() - t0, 1)
        self._emit("done", 100, f"Done in {result.duration_secs}s")
        return result

    # ------------------------------------------------------------------
    # Ping
    # ------------------------------------------------------------------

    def run_ping(self, count: int = 3) -> list[PingResult]:
        results = []
        for host, port, label in PING_HOSTS:
            latencies = []
            for _ in range(count):
                ms = self._tcp_ping(host, port)
                if ms >= 0:
                    latencies.append(ms)
            if latencies:
                avg = sum(latencies) / len(latencies)
                results.append(PingResult(host, label, round(avg, 1), True))
            else:
                results.append(PingResult(host, label, -1, False))
        return results

    def _tcp_ping(self, host: str, port: int) -> float:
        """TCP connect latency in ms. Returns -1 if unreachable."""
        try:
            t0 = time.perf_counter()
            sock = socket.create_connection((host, port),
                                            timeout=self.PING_TIMEOUT)
            ms = (time.perf_counter() - t0) * 1000
            sock.close()
            return round(ms, 2)
        except Exception:
            return -1.0

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    def run_dns(self) -> tuple[list, float]:
        results = []
        times = []
        for domain in DNS_TEST_DOMAINS:
            try:
                t0 = time.perf_counter()
                socket.getaddrinfo(domain, None)
                ms = (time.perf_counter() - t0) * 1000
                results.append({"domain": domain, "ms": round(ms, 1)})
                times.append(ms)
            except Exception:
                results.append({"domain": domain, "ms": -1})
        avg = round(sum(t for t in times if t > 0) / max(len(times), 1), 1)
        return results, avg

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    def run_download(self) -> dict:
        for url in DOWNLOAD_URLS:
            result = self._try_download(url)
            if result.get("mbps", 0) > 0:
                return result
        return {"mbps": 0, "error": "All download servers failed"}

    def _try_download(self, url: str) -> dict:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "SpeedTest/1.0"})
            t0 = time.perf_counter()
            total_bytes = 0

            with urllib.request.urlopen(req, timeout=self.DOWNLOAD_TIMEOUT,
                                        context=self._ctx) as resp:
                while True:
                    chunk = resp.read(self.DOWNLOAD_CHUNK)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    elapsed = time.perf_counter() - t0
                    # Report progress
                    mbps = (total_bytes * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
                    self._emit("download",
                               35 + min(38, int(total_bytes / 100_000)),
                               f"↓ {mbps:.1f} Mbps  ({total_bytes/1024/1024:.1f} MB)")
                    if elapsed > self.DOWNLOAD_TIMEOUT:
                        break

            elapsed = time.perf_counter() - t0
            if elapsed <= 0 or total_bytes == 0:
                return {"mbps": 0, "error": "No data received"}

            mbps = round((total_bytes * 8) / (elapsed * 1_000_000), 2)
            return {
                "mbps":   mbps,
                "mb":     round(total_bytes / 1_000_000, 2),
                "secs":   round(elapsed, 2),
                "server": url.split("/")[2],
            }
        except Exception as e:
            return {"mbps": 0, "error": str(e)[:60]}

    # ------------------------------------------------------------------
    # Upload
    # ------------------------------------------------------------------

    def run_upload(self) -> dict:
        try:
            data = os.urandom(self.UPLOAD_SIZE_MB * 1_000_000)
            req  = urllib.request.Request(
                UPLOAD_URL,
                data=data,
                method="POST",
                headers={
                    "Content-Type": "application/octet-stream",
                    "User-Agent":   "SpeedTest/1.0",
                    "Content-Length": str(len(data)),
                },
            )
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=self.UPLOAD_TIMEOUT,
                                        context=self._ctx) as resp:
                resp.read()

            elapsed = time.perf_counter() - t0
            if elapsed <= 0:
                return {"mbps": 0}

            mbps = round((len(data) * 8) / (elapsed * 1_000_000), 2)
            return {
                "mbps": mbps,
                "mb":   round(len(data) / 1_000_000, 2),
                "secs": round(elapsed, 2),
            }
        except Exception as e:
            return {"mbps": 0, "error": str(e)[:60]}

    # ------------------------------------------------------------------
    # Public IP
    # ------------------------------------------------------------------

    def _get_public_ip(self) -> str:
        for url in ["https://api.ipify.org", "https://checkip.amazonaws.com"]:
            try:
                with urllib.request.urlopen(url, timeout=5,
                                            context=self._ctx) as r:
                    return r.read().decode().strip()
            except Exception:
                pass
        return "unknown"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _emit(self, stage: str, pct: float, msg: str):
        if self._progress:
            try:
                self._progress(stage, pct, msg)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# CLI runner
# ─────────────────────────────────────────────────────────────────────────────

def run_speed_test_cli(run_upload: bool = True) -> SpeedTestResult:
    """Interactive CLI speed test with Rich progress display."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.progress import (Progress, SpinnerColumn,
                                   BarColumn, TextColumn, TimeElapsedColumn)
        from rich.table import Table
        from rich.live import Live
        from rich.text import Text
        console = Console()
    except ImportError:
        st = SpeedTest()
        result = st.run(run_upload=run_upload)
        print(result.summary())
        return result

    console.print(Panel(
        "[bold cyan]DSRP — Internet Speed Test[/bold cyan]\n"
        "[dim]No external packages needed · Uses stdlib urllib[/dim]",
        border_style="cyan",
    ))

    last_msg = ["Initialising..."]
    last_pct = [0.0]

    def on_progress(stage, pct, msg):
        last_msg[0] = msg
        last_pct[0] = pct

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[cyan]{task.percentage:>3.0f}%[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running speed test...", total=100)

        # Patch progress into callback
        def _cb(stage, pct, msg):
            progress.update(task, completed=pct, description=f"[dim]{msg}[/dim]")

        st = SpeedTest(progress_callback=_cb)
        result = st.run(run_upload=run_upload)

    # ── Results panel ─────────────────────────────────────────────────
    qc = result.quality_color
    console.print(Panel(
        f"[bold]Public IP :[/bold] {result.isp_ip}\n"
        f"[bold]Quality   :[/bold] [{qc}]{result.quality}[/{qc}]",
        title="Speed Test Complete",
        border_style="cyan",
    ))

    # Main metrics table
    t = Table(show_lines=True, expand=True)
    t.add_column("Test",    style="bold")
    t.add_column("Result",  style="bold")
    t.add_column("Details", style="dim")

    dl_color = "#3FB950" if result.download_mbps >= 10 else \
               "#F0B429" if result.download_mbps >= 1 else "#FF7B72"
    ul_color = "#3FB950" if result.upload_mbps >= 5 else \
               "#F0B429" if result.upload_mbps >= 1 else "#FF7B72"
    ping_color = "#3FB950" if result.best_ping_ms < 50 else \
                 "#F0B429" if result.best_ping_ms < 150 else "#FF7B72"

    t.add_row(
        "⬇ Download",
        f"[{dl_color}]{result.download_mbps:.2f} Mbps[/{dl_color}]",
        f"{result.download_mb:.1f} MB in {result.download_secs:.1f}s"
        f"{' — ' + result.download_error if result.download_error else ''}",
    )
    t.add_row(
        "⬆ Upload",
        f"[{ul_color}]{result.upload_mbps:.2f} Mbps[/{ul_color}]"
        if result.upload_mbps > 0 else "[dim]skipped[/dim]",
        f"{result.upload_mb:.1f} MB in {result.upload_secs:.1f}s"
        if result.upload_mbps > 0 else result.upload_error or "",
    )
    t.add_row(
        "📶 Ping (best)",
        f"[{ping_color}]{result.best_ping_ms:.1f} ms[/{ping_color}]"
        if result.best_ping_ms > 0 else "[red]unreachable[/red]",
        f"avg {result.avg_ping_ms:.1f} ms across {len(result.ping_results)} servers",
    )
    t.add_row(
        "🌐 DNS",
        f"{result.dns_avg_ms:.1f} ms avg",
        " | ".join(f"{d['domain'].split('.')[0]}: {d['ms']:.0f}ms"
                   for d in result.dns_results if d['ms'] > 0),
    )
    console.print(t)

    # Per-server ping table
    ping_t = Table(title="Ping per server", show_lines=False, box=None)
    ping_t.add_column("Server",  style="dim")
    ping_t.add_column("IP",      style="dim")
    ping_t.add_column("Latency", width=12)
    for pr in result.ping_results:
        if pr.reachable:
            pc = "#3FB950" if pr.latency_ms < 50 else \
                 "#F0B429" if pr.latency_ms < 150 else "#FF7B72"
            ping_t.add_row(pr.label, pr.host,
                           f"[{pc}]{pr.latency_ms:.1f} ms[/{pc}]")
        else:
            ping_t.add_row(pr.label, pr.host, "[red]unreachable[/red]")
    console.print(ping_t)

    console.print(f"\n[dim]Total test time: {result.duration_secs}s[/dim]")
    return result