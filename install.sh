#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  DSRP — Device Security Research Platform
#  Automatic Installer for Termux
#
#  Usage:
#    chmod +x install.sh
#    ./install.sh
#    ./install.sh --full      (install semua termasuk opsional)
#    ./install.sh --minimal   (hanya yang wajib)
#    ./install.sh --check     (cek status instalasi saja)
# ============================================================

set -e

# ── Warna output ──────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

ok()   { echo -e "${GREEN}  ✓${NC} $1"; }
warn() { echo -e "${YELLOW}  ⚠${NC} $1"; }
err()  { echo -e "${RED}  ✗${NC} $1"; }
info() { echo -e "${CYAN}  →${NC} $1"; }
hdr()  { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "  $(printf '─%.0s' {1..50})"; }

# ── Parse arguments ───────────────────────────────────────────
MODE="default"
for arg in "$@"; do
    case $arg in
        --full)    MODE="full" ;;
        --minimal) MODE="minimal" ;;
        --check)   MODE="check" ;;
        --help|-h)
            echo "Usage: ./install.sh [--full|--minimal|--check]"
            echo "  (no flag)  Install core + recommended packages"
            echo "  --full     Install everything including heavy optional packages"
            echo "  --minimal  Install only the bare minimum to run"
            echo "  --check    Check what is/isn't installed without installing"
            exit 0
            ;;
    esac
done

# ── Banner ────────────────────────────────────────────────────
clear
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
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
EOF
echo -e "${NC}"
echo -e "  ${BOLD}Device Security Research Platform v1.0${NC}"
echo -e "  ${CYAN}Installer — Mode: ${BOLD}${MODE}${NC}"
echo ""

# ── Check we're in Termux ─────────────────────────────────────
if [ ! -d "/data/data/com.termux" ]; then
    warn "Not running in Termux — some steps may not apply."
fi

# ── Check Python version ──────────────────────────────────────
hdr "Checking Python"
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    PY_MAJOR=$(echo $PY_VERSION | cut -d'.' -f1)
    PY_MINOR=$(echo $PY_VERSION | cut -d'.' -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        ok "Python $PY_VERSION (required: 3.11+)"
    else
        warn "Python $PY_VERSION found, but 3.11+ recommended"
        warn "Some features may not work correctly"
    fi
else
    err "Python 3 not found — install with: pkg install python"
    exit 1
fi

# ── Check mode ────────────────────────────────────────────────
if [ "$MODE" = "check" ]; then
    hdr "Dependency Check"

    PACKAGES=(
        "rich:Core UI"
        "psutil:System monitoring"
        "textual:Full Textual dashboard"
        "sklearn:AI/ML features"
        "networkx:Network graph analysis"
        "matplotlib:Graph PNG export"
        "requests:Threat intel API"
        "nmap:Network scanning (python-nmap)"
        "scapy:Deep packet capture"
    )

    ALL_OK=true
    for entry in "${PACKAGES[@]}"; do
        pkg="${entry%%:*}"
        desc="${entry##*:}"
        if python3 -c "import $pkg" 2>/dev/null; then
            ok "${pkg} — ${desc}"
        else
            warn "${pkg} — ${desc} [NOT INSTALLED]"
            ALL_OK=false
        fi
    done

    # System tools
    echo ""
    info "System tools:"
    for tool in nmap arp-scan adb; do
        if command -v $tool &>/dev/null; then
            ok "$tool"
        else
            warn "$tool [not found]"
        fi
    done

    echo ""
    if $ALL_OK; then
        ok "All packages installed!"
    else
        warn "Some packages missing — run ./install.sh to install"
    fi
    exit 0
fi

# ── Step 1: Update Termux packages ───────────────────────────
hdr "Step 1 — Update Termux"
info "Running pkg update..."
pkg update -y 2>/dev/null && ok "Termux packages updated" || warn "Update had warnings (continuing)"

# ── Step 2: System packages ───────────────────────────────────
hdr "Step 2 — System Packages"

SYS_PACKAGES="python nmap iproute2"
if [ "$MODE" = "full" ]; then
    SYS_PACKAGES="$SYS_PACKAGES arp-scan tcpdump"
fi

info "Installing: $SYS_PACKAGES"
for pkg in $SYS_PACKAGES; do
    if pkg install -y "$pkg" 2>/dev/null; then
        ok "$pkg"
    else
        warn "$pkg — skipped (may not be available)"
    fi
done

# ── Step 3: Core Python packages (required) ───────────────────
hdr "Step 3 — Core Python Packages (Required)"

CORE_PACKAGES=(
    "rich"
    "psutil"
)

for pkg in "${CORE_PACKAGES[@]}"; do
    info "Installing $pkg..."
    if pip install "$pkg" --break-system-packages -q 2>/dev/null || \
       pip3 install "$pkg" --break-system-packages -q 2>/dev/null || \
       python3 -m pip install "$pkg" --break-system-packages -q 2>/dev/null; then
        ok "$pkg"
    else
        err "$pkg — FAILED (try manually: pip install $pkg --break-system-packages)"
    fi
done

# ── Step 4: Recommended packages ─────────────────────────────
if [ "$MODE" != "minimal" ]; then
    hdr "Step 4 — Recommended Packages"

    RECOMMENDED=(
        "textual:Full Textual dashboard GUI"
        "scikit-learn:AI malware detection (ML)"
        "requests:Threat intelligence API calls"
        "python-nmap:Network device scanning"
    )

    for entry in "${RECOMMENDED[@]}"; do
        pkg="${entry%%:*}"
        desc="${entry##*:}"
        info "Installing $pkg ($desc)..."
        if pip install "$pkg" --break-system-packages -q 2>/dev/null || \
           python3 -m pip install "$pkg" --break-system-packages -q 2>/dev/null; then
            ok "$pkg"
        else
            warn "$pkg — failed, some features will be disabled"
        fi
    done
fi

# ── Step 5: Full / optional packages ─────────────────────────
if [ "$MODE" = "full" ]; then
    hdr "Step 5 — Optional Packages (Full Install)"

    OPTIONAL=(
        "networkx:Network graph analysis"
        "matplotlib:Graph PNG export"
        "scapy:Deep packet capture (needs root)"
    )

    for entry in "${OPTIONAL[@]}"; do
        pkg="${entry%%:*}"
        desc="${entry##*:}"
        info "Installing $pkg ($desc)..."
        if pip install "$pkg" --break-system-packages -q 2>/dev/null || \
           python3 -m pip install "$pkg" --break-system-packages -q 2>/dev/null; then
            ok "$pkg"
        else
            warn "$pkg — failed (optional, continuing)"
        fi
    done
fi

# ── Step 6: Create data directories ──────────────────────────
hdr "Step 6 — Initialise Data Directory"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
REPORTS_DIR="$DATA_DIR/reports"
GRAPHS_DIR="$DATA_DIR/graphs"

mkdir -p "$DATA_DIR" "$REPORTS_DIR" "$GRAPHS_DIR"
ok "data/ directory ready"
ok "data/reports/ ready"
ok "data/graphs/ ready"

# ── Step 7: Create __init__.py files ─────────────────────────
hdr "Step 7 — Package Init Files"

PACKAGES_DIRS=(
    "core" "network" "system" "intel" "sandbox"
    "ai" "ids" "analysis" "apk" "defense" "report" "ui" "data"
)

for dir in "${PACKAGES_DIRS[@]}"; do
    INIT_FILE="$SCRIPT_DIR/$dir/__init__.py"
    if [ -d "$SCRIPT_DIR/$dir" ]; then
        if [ ! -f "$INIT_FILE" ]; then
            touch "$INIT_FILE"
            ok "Created $dir/__init__.py"
        else
            ok "$dir/__init__.py exists"
        fi
    else
        warn "Directory $dir/ not found — create it and add files"
    fi
done

# Root __init__.py
touch "$SCRIPT_DIR/__init__.py" 2>/dev/null && ok "Root __init__.py ready"

# ── Step 8: Verify config.toml ────────────────────────────────
hdr "Step 8 — Configuration"

CONFIG_FILE="$SCRIPT_DIR/config.toml"
if [ -f "$CONFIG_FILE" ]; then
    ok "config.toml found"
else
    warn "config.toml not found — creating default config"
    python3 -c "
from pathlib import Path
# Config will be auto-created when dsrp.py runs
print('  Will be created on first run')
"
fi

# ── Step 9: Quick smoke test ──────────────────────────────────
hdr "Step 9 — Smoke Test"

python3 -c "
import sys
ok = True
modules = [
    ('psutil',   'System monitoring'),
    ('rich',     'Terminal UI'),
    ('pathlib',  'File system'),
    ('sqlite3',  'Database'),
    ('asyncio',  'Async'),
]
for mod, desc in modules:
    try:
        __import__(mod)
        print(f'  ✓ {mod} ({desc})')
    except ImportError:
        print(f'  ✗ {mod} ({desc}) — MISSING')
        ok = False
sys.exit(0 if ok else 1)
" && ok "Core imports successful" || err "Some core imports failed"

# ── Done ──────────────────────────────────────────────────────
hdr "Installation Complete"

echo ""
echo -e "  ${GREEN}${BOLD}DSRP is ready to run!${NC}"
echo ""
echo -e "  ${BOLD}Quick start:${NC}"
echo -e "  ${CYAN}  cd $(dirname "$0")${NC}"
echo -e "  ${CYAN}  python dsrp.py${NC}               # Full dashboard"
echo -e "  ${CYAN}  python dsrp.py --lite${NC}         # Rich fallback (no Textual)"
echo -e "  ${CYAN}  python dsrp.py status${NC}         # Check all dependencies"
echo -e "  ${CYAN}  python dsrp.py scan${NC}           # Quick app scan"
echo ""
echo -e "  ${BOLD}Optional — set API keys for threat intel:${NC}"
echo -e "  ${YELLOW}  export VT_API_KEY=\"your_virustotal_key\"${NC}"
echo -e "  ${YELLOW}  export ABUSEIPDB_API_KEY=\"your_key\"${NC}"
echo -e "  ${YELLOW}  export OTX_API_KEY=\"your_key\"${NC}"
echo ""
echo -e "  ${BOLD}Or edit config.toml to make keys permanent.${NC}"
echo ""