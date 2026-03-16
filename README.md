# DSRP — Device Security Research Platform

```
▓█████▄   ██████  ██▀███   ██▓███  
▒██▀ ██▌▒██    ▒ ▓██ ▒ ██▒▓██░  ██▒
░██   █▌░ ▓██▄   ▓██ ░▄█ ▒▓██░ ██▓▒
░▓█▄   ▌  ▒   ██▒▒██▀▀█▄  ▒██▄█▓▒ ▒
░▒████▓ ▒██████▒▒░██▓ ▒██▒▒██▒ ░  ░
 ▒▒▓  ▒ ▒ ▒▓▒ ▒ ░░ ▒▓ ░▒▓░▒▓▒░ ░  ░
 ░ ▒  ▒ ░ ░▒  ░ ░  ░▒ ░ ▒░░▒ ░     
 ░ ░  ░ ░  ░  ░    ░░   ░ ░░       
   ░          ░     ░              
 ░                                 
```

**Device Security Research Platform v1.1**

A modular security research toolkit for Android (Termux), Linux, and Windows. Combines app scanning, network monitoring, AI threat detection, and autonomous defense — no root required for most features.

---

## Quick Start

```bash
chmod +x install.sh && ./install.sh
python asrp.py
```

---

## Features at a Glance

| Module | What it does |
|--------|-------------|
| **App Scanner** | Scans installed apps for malware, trackers, dangerous permissions |
| **Network Monitor** | Per-app connection tracking, DNS monitoring, WiFi discovery |
| **AI Security** | IsolationForest anomaly detection + RandomForest malware classifier |
| **IDS Engine** | 7 rules: port scan, DNS tunnel, beaconing, exfil, ADB, C2, SNI |
| **Threat Intel** | VirusTotal, AbuseIPDB, AlienVault OTX reputation cache |
| **APK Intelligence** | Binary XML parser, DEX scan, cross-platform (Android/Linux/Windows) |
| **Speed Test** | Download, upload, ping, DNS — no external packages |
| **VPN Leak Detector** | DNS leak, IP leak, split tunnel detection |
| **SSL/TLS Analyzer** | APK bypass patterns + live certificate checker |
| **WiFi Security** | Open/WEP/WPS networks, evil twin detection |
| **Autonomous Defense** | Auto-block trackers and C2 with policy engine |
| **Debloat Scanner** | Android/Linux/Windows bloatware detection and removal |
| **Security Reports** | JSON/TXT/Markdown reports with risk scoring |

---

## Installation

### Termux (Android)

```bash
chmod +x install.sh

./install.sh              # Core + recommended packages
./install.sh --minimal    # Bare minimum (psutil + rich)
./install.sh --full       # Everything including optional
./install.sh --check      # Show what's installed
```

### Manual

```bash
# Termux
pkg install python nmap iproute2 -y
pip install psutil rich textual scikit-learn requests python-nmap --break-system-packages

# Linux / Windows
pip install psutil rich textual scikit-learn requests python-nmap networkx matplotlib
```
---

## Root vs No-Root

| Feature | No Root | With Root |
|---------|---------|-----------|
| App manifest scan | ✅ dumpsys | ✅ Full |
| User APK DEX scan | ✅ Usually | ✅ Always |
| System APK DEX scan | ❌ | ✅ Full |
| Network tracking | ✅ /proc | ✅ Full |
| Packet capture | ❌ | ✅ Scapy |
| iptables blocking | ❌ | ✅ Kernel |
| Privacy hardening | ✅ pm disable | ✅ System |


## Commands

### Unified launcher

```bash
python asrp.py                    # Full Textual dashboard (all stages)
python asrp.py --lite             # Rich fallback (no Textual needed)
python asrp.py --mode STRICT      # Override defense mode
python asrp.py status             # Dependency check + config summary
```

### Quick commands

```bash
python asrp.py scan               # App malware scan
python asrp.py network            # Network monitor
python asrp.py defend             # Autonomous defense console
python asrp.py lab                # Security lab menu
python asrp.py report             # Generate security report
python asrp.py speed              # Internet speed test
python asrp.py vpn                # VPN leak test
python asrp.py ssl                # Live SSL/TLS certificate check
python asrp.py ssl /path/app.apk  # APK SSL bypass analysis
python asrp.py wifi               # WiFi security scan
python asrp.py apk                # Scan all installed apps
python asrp.py block evil.com     # Block a domain
python asrp.py unblock evil.com   # Unblock a domain
```

### Stage-specific

```bash
python main.py                    # Stage 1 — app scanner only
python network_analysis.py        # Stage 2 — network monitor only
python security_analysis.py       # Stage 3 — IDS + AI only
python lab_analysis.py            # Stage 4 — security lab only
python autonomous_defense.py      # Stage 5 — defense only

# network_analysis.py flags
python network_analysis.py --speed
python network_analysis.py --vpn
python network_analysis.py --ssl
python network_analysis.py --wifi
```

---

## Dashboard Tabs

| Tab | Contents | Buttons |
|-----|----------|---------|
| **Dashboard** | CPU, RAM, network, alerts summary | — |
| **Network** | Connections, trackers, DNS, WiFi devices, speed test, VPN leak, WiFi security | Speed Test, VPN Leak Test, Scan WiFi |
| **Security** | IDS alerts, AI anomaly detector, feature window, SSL/TLS scanner | Live TLS Scan, Scan APK |
| **Defense** | Mode selector, blocklist, incidents, policy rules, debloat | MONITOR / DEFENSIVE / STRICT, Scan Bloatware, Harden |
| **Lab** | Network graph, C2 candidates, threat intel, ML predictions | Refresh Graph, APK Analysis, IOC Update, Gen Report |
| **Report** | Risk metrics, report preview, saved reports list | Generate, Save JSON, Save Markdown, Delete Latest, Delete All |

### Keyboard shortcuts

```
1–6   Switch tabs          s   App scan
r     Refresh              w   WiFi device scan
q     Quit                 ?   Help
```

---

## Project Structure

```
dsrp/
├── asrp.py                  ← Entry point
├── core_engine.py           ← Orchestrator
├── config.toml              ← Configuration
├── config.py                ← Config loader
├── logger.py                ← Logging
├── resource_limiter.py      ← CPU/RAM governor
├── install.sh               ← Installer
│
├── core/                    ← Stage 1: App scanning
├── network/                 ← Stage 2 + network security
│   ├── speed_test.py
│   ├── vpn_leak_detector.py
│   ├── ssl_tls_analyzer.py
│   └── wifi_security_checker.py
├── ai/                      ← Stage 3: ML models
├── ids/                     ← Stage 3: Intrusion detection
├── intel/                   ← Threat intelligence
├── analysis/                ← Stage 4: Advanced analysis
├── apk/                     ← APK intelligence
│   ├── axml_parser.py         ← Binary XML parser (no aapt)
│   ├── apk_analyzer_cross.py  ← Cross-platform analysis
│   └── installed_apk_scanner.py
├── defense/                 ← Stage 5: Autonomous defense
├── report/                  ← Reporting
├── system/                  ← System tools
│   ├── proc_stats.py          ← /proc reader (no psutil needed)
│   └── debloat_cross.py       ← Cross-platform debloat
├── sandbox/                 ← APK sandbox
├── ui/                      ← UI views
│   └── dashboard.py           ← Full Textual dashboard
└── data/                    ← Runtime data (auto-created)
    ├── tracker_domains.json
    ├── tracker_signatures.json
    ├── dsrp.log
    ├── blocklist.db
    ├── incidents.db
    ├── reputation_cache.db
    └── reports/
```

---

## IDS Rules

| ID | Name | Severity | Trigger |
|----|------|----------|---------|
| IDS-001 | Port Scan | HIGH | 10+ distinct ports from same source in 5s |
| IDS-002 | DNS Tunneling | HIGH | Label length > 40 chars or 80+ queries/min |
| IDS-003 | Beaconing | HIGH | Interval jitter < 15% over 6+ packets |
| IDS-004 | Data Exfiltration | HIGH | 10 MB+ outbound to single IP in 60s |
| IDS-005 | ADB over TCP | CRITICAL | Any traffic to port 5555 |
| IDS-006 | Suspicious Port | MEDIUM | Traffic to known C2/RAT ports |
| IDS-007 | Suspicious SNI | MEDIUM | TLS SNI matches malicious patterns |

---

## Defense Modes

| Mode | Trackers | Malicious | C2 | Suspicious | Flag Apps |
|------|----------|-----------|-----|------------|-----------|
| MONITOR | Log | Log | Log | — | No |
| DEFENSIVE | **Block** | **Block** | **Block** | Log | Yes |
| STRICT | **Block** | **Block** | **Block** | **Block** | Yes |

---

## Platform Support

| Feature | Android | Linux | Windows |
|---------|---------|-------|---------|
| Dashboard | ✅ | ✅ | ✅ |
| App scan | ✅ | — | — |
| Network monitor | ✅ | ✅ | ✅ (partial) |
| APK analysis | ✅ | ✅ | ✅ |
| Speed test | ✅ | ✅ | ✅ |
| VPN leak detector | ✅ | ✅ | ✅ |
| SSL/TLS analyzer | ✅ | ✅ | ✅ |
| WiFi security | ✅ | ✅ | ✅ |
| Debloat scanner | ✅ | ✅ | ✅ |
| AI / IDS | ✅ | ✅ | ✅ |

---


**APK analysis returns empty**

Real APKs use binary XML (AXML format). DSRP includes a built-in AXML parser. If analysis is still empty, the APK file may be inaccessible — copy it to `/sdcard/Download/` first:
```bash
pm path com.example.app          # get APK path
cp <path> /sdcard/Download/app.apk
python asrp.py ssl /sdcard/Download/app.apk
```

**AI Anomaly shows "Warm-up"**

Normal — needs 20 data windows (~5 minutes of network activity) before the model is ready.

**WiFi scan returns no results**

Install `iw` or `arp-scan`:
```bash
pkg install iw arp-scan
```

---

## Privacy

DSRP does not send any data externally unless threat intel API keys are configured and `enable_remote_intel = true`. All data is stored locally in `data/`. Network monitoring captures metadata only — no payload content (unless Scapy is explicitly used for deep packet inspection).

---

## License

MIT — see [LICENSE](LICENSE).

Use responsibly. This tool is designed for security research on devices you own or have explicit permission to test.

---

*DSRP v1.1 · 78 Python files · 24,000+ lines · Android · Linux · Windows*
