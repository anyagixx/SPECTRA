#!/usr/bin/env bash
#
# SPECTRA — interactive client launcher for Ubuntu Desktop.
#
# Usage:
#   ./scripts/run-client.sh                        # interactive mode
#   ./scripts/run-client.sh --server x.com:443 --psk HEX   # non-interactive
#
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fatal() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

install_client_packages() {
  local packages=("$@")
  [[ ${#packages[@]} -eq 0 ]] && return 0

  info "Installing required packages: ${packages[*]}"
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${packages[@]}" >/dev/null
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y -q "${packages[@]}"
  elif command -v yum &>/dev/null; then
    sudo yum install -y -q "${packages[@]}"
  elif command -v apk &>/dev/null; then
    sudo apk add --no-cache "${packages[@]}"
  elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm "${packages[@]}"
  else
    fatal "No supported package manager found. Install manually: ${packages[*]}"
  fi
}

ensure_client_command() {
  local command_name="$1"
  local package_name="${2:-$1}"

  if ! command -v "$command_name" &>/dev/null; then
    install_client_packages "$package_name"
  fi
}

ensure_client_downloader() {
  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    install_client_packages curl
  fi
}

download_file() {
  local url="$1"
  local output="$2"

  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$output"
  elif command -v wget &>/dev/null; then
    wget -q "$url" -O "$output"
  else
    fatal "Neither curl nor wget is installed."
  fi
}

# ─── Defaults ─────────────────────────────────────────────────────────────────
SERVER=""
PSK=""
SNI=""
SOCKS="127.0.0.1:1080"
PROFILE=""
INSECURE=""
INTERACTIVE=0
[[ -t 0 ]] && INTERACTIVE=1

# ─── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)   SERVER="$2";   shift 2 ;;
    --psk)      PSK="$2";      shift 2 ;;
    --sni)      SNI="$2";      shift 2 ;;
    --socks)    SOCKS="$2";    shift 2 ;;
    --insecure) INSECURE="--insecure"; shift ;;
    --help|-h)
      echo "Usage: $0 [--server HOST:PORT] [--psk HEX] [--sni DOMAIN] [--socks ADDR] [--insecure]"
      exit 0 ;;
    *) fatal "Unknown argument: $1" ;;
  esac
done

# ─── Locate project root ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

if [[ ! -f "go.mod" ]]; then
  fatal "Cannot find project root. Run this script from the SPECTRA directory."
fi

PROFILE="${PROJECT_DIR}/configs/profiles/geforcenow.json"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║           SPECTRA Client Launcher                ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ─── Interactive prompts (if not provided via flags) ──────────────────────────
if [[ -z "$SERVER" ]]; then
  [[ "$INTERACTIVE" -eq 1 ]] || fatal "--server HOST:PORT is required in non-interactive mode."
  echo -e "${CYAN}Enter server address (e.g. gaming.example.com:443):${NC}"
  read -rp "> " SERVER
  [[ -z "$SERVER" ]] && fatal "Server address is required."
fi

if [[ -z "$PSK" ]]; then
  [[ "$INTERACTIVE" -eq 1 ]] || fatal "--psk HEX is required in non-interactive mode."
  echo -e "${CYAN}Enter PSK (64 hex chars, from server deployment):${NC}"
  read -rp "> " PSK
  [[ -z "$PSK" ]] && fatal "PSK is required."
fi

if [[ ${#PSK} -ne 64 ]]; then
  fatal "PSK must be exactly 64 hex characters. Got ${#PSK}."
fi

# Auto-derive SNI from server address (strip port)
if [[ -z "$SNI" ]]; then
  SNI="${SERVER%%:*}"
  if [[ "$INTERACTIVE" -eq 1 ]]; then
    echo -e "${CYAN}SNI domain [${SNI}]:${NC}"
    read -rp "> " INPUT_SNI
    [[ -n "$INPUT_SNI" ]] && SNI="$INPUT_SNI"
  fi
fi

if [[ "$INTERACTIVE" -eq 1 ]]; then
  echo -e "${CYAN}SOCKS5 listen address [${SOCKS}]:${NC}"
  read -rp "> " INPUT_SOCKS
  [[ -n "$INPUT_SOCKS" ]] && SOCKS="$INPUT_SOCKS"
fi

# ─── Install Go if missing ───────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
  info "Go not found. Installing Go 1.22.5..."
  GO_TAR="go1.22.5.linux-amd64.tar.gz"
  ensure_client_downloader
  ensure_client_command tar
  download_file "https://go.dev/dl/${GO_TAR}" "/tmp/${GO_TAR}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"
  rm "/tmp/${GO_TAR}"
  export PATH=$PATH:/usr/local/go/bin
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  ok "Go installed: $(go version)"
fi

# ─── Build client ────────────────────────────────────────────────────────────
if [[ ! -f "$PROJECT_DIR/spectra-client" ]] || [[ "$PROJECT_DIR/go.mod" -nt "$PROJECT_DIR/spectra-client" ]]; then
  info "Building spectra-client..."
  go build -ldflags="-s -w" -o spectra-client ./cmd/spectra-client
  ok "Built: spectra-client"
else
  ok "spectra-client binary is up to date"
fi

# ─── Apply sysctl tuning (optional) ──────────────────────────────────────────
SYSCTL_CONF="$PROJECT_DIR/deployments/sysctl/99-spectra-quic.conf"
if [[ -f "$SYSCTL_CONF" ]]; then
  CURRENT_RMEM=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
  if [[ "$CURRENT_RMEM" -lt 8388608 ]]; then
    info "UDP buffers are small ($CURRENT_RMEM). Applying QUIC tuning..."
    if [[ -x "$PROJECT_DIR/scripts/quic-tune.sh" ]]; then
      "$PROJECT_DIR/scripts/quic-tune.sh" enable
    else
      warn "QUIC tuning helper is missing. Run from a complete SPECTRA checkout."
    fi
  else
    ok "UDP buffers already tuned (rmem_max=$CURRENT_RMEM)"
  fi
fi

# ─── Launch ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}Starting SPECTRA client...${NC}"
echo "  Server:  $SERVER"
echo "  SNI:     $SNI"
echo "  SOCKS5:  $SOCKS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${YELLOW}After connection, test with:${NC}"
echo "  curl --socks5 ${SOCKS} https://ifconfig.me"
echo "  curl --socks5 ${SOCKS} https://httpbin.org/ip"
echo ""
echo "Press Ctrl+C to stop."
echo ""

exec "$PROJECT_DIR/spectra-client" \
  --psk "$PSK" \
  --server "$SERVER" \
  --sni "$SNI" \
  --socks "$SOCKS" \
  --profile "$PROFILE" \
  $INSECURE
