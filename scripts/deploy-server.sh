#!/usr/bin/env bash
#
# SPECTRA — one-command server deployment on a clean VPS.
#
# Usage (from a cloned repo):
#   sudo ./scripts/deploy-server.sh \
#     --cert /etc/letsencrypt/live/example.com/fullchain.pem \
#     --key  /etc/letsencrypt/live/example.com/privkey.pem
#
# Or with an existing PSK:
#   sudo ./scripts/deploy-server.sh \
#     --cert /path/to/cert.pem --key /path/to/key.pem --psk YOUR_HEX_PSK
#
# Remote one-liner (after pushing to GitHub):
#   ssh root@YOUR_VPS 'bash -s' < scripts/deploy-server.sh \
#     -- --cert /path/cert.pem --key /path/key.pem --repo https://github.com/anyagixx/SPECTRA.git
#
set -euo pipefail

# ─── Defaults ─────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/spectra"
LISTEN=":443"
PROFILE="configs/profiles/geforcenow.json"
SERVICE_NAME="spectra"
SERVICE_USER="root"
GO_VERSION="1.22.5"
ENV_DIR="/etc/spectra"
CERT=""
KEY=""
PSK=""
REPO=""
DOMAIN=""
export PATH="$PATH:/usr/local/go/bin"

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fatal() { err "$@"; exit 1; }

install_packages() {
  local packages=("$@")
  [[ ${#packages[@]} -eq 0 ]] && return 0

  info "Installing required packages: ${packages[*]}"
  if command -v apt-get &>/dev/null; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${packages[@]}" >/dev/null
  elif command -v dnf &>/dev/null; then
    dnf install -y -q "${packages[@]}"
  elif command -v yum &>/dev/null; then
    yum install -y -q "${packages[@]}"
  elif command -v apk &>/dev/null; then
    apk add --no-cache "${packages[@]}"
  elif command -v pacman &>/dev/null; then
    pacman -Sy --noconfirm "${packages[@]}"
  else
    fatal "No supported package manager found. Install manually: ${packages[*]}"
  fi
}

ensure_command() {
  local command_name="$1"
  local package_name="${2:-$1}"

  if ! command -v "$command_name" &>/dev/null; then
    install_packages "$package_name"
  fi
}

ensure_downloader() {
  if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    install_packages curl
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

env_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//\$/\\\$}"
  value="${value//\`/\\\`}"
  printf '%s' "$value"
}

# ─── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cert)    CERT="$2";    shift 2 ;;
    --key)     KEY="$2";     shift 2 ;;
    --psk)     PSK="$2";     shift 2 ;;
    --repo)    REPO="$2";    shift 2 ;;
    --domain)  DOMAIN="$2";  shift 2 ;;
    --listen)  LISTEN="$2";  shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 --cert PATH --key PATH [--psk HEX] [--repo URL] [--domain DOMAIN] [--listen ADDR] [--dir PATH]"
      exit 0 ;;
    *) fatal "Unknown argument: $1" ;;
  esac
done

# ─── Validate ─────────────────────────────────────────────────────────────────
[[ -z "$CERT" ]] && fatal "--cert is required (path to TLS certificate, e.g. /etc/letsencrypt/live/DOMAIN/fullchain.pem)"
[[ -z "$KEY"  ]] && fatal "--key is required (path to TLS private key, e.g. /etc/letsencrypt/live/DOMAIN/privkey.pem)"
[[ -f "$CERT" ]] || fatal "Certificate file not found: $CERT"
[[ -f "$KEY"  ]] || fatal "Key file not found: $KEY"

if [[ $(id -u) -ne 0 ]]; then
  fatal "This script must be run as root (sudo)."
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         SPECTRA Server Deployment                ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ─── Step 0: Bootstrap required system tools ─────────────────────────────────
ensure_downloader
ensure_command tar
ensure_command openssl
if [[ -n "$REPO" ]]; then
  ensure_command git
else
  ensure_command rsync
fi

# ─── Step 1: Install Go if missing ───────────────────────────────────────────
if command -v go &>/dev/null; then
  ok "Go already installed: $(go version)"
else
  info "Installing Go ${GO_VERSION}..."
  cd /tmp
  download_file "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" go.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf go.tar.gz
  rm go.tar.gz
  export PATH=$PATH:/usr/local/go/bin

  # Persist in profile
  if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
  fi

  ok "Go $(go version) installed"
fi

# ─── Step 2: Get source code ─────────────────────────────────────────────────
if [[ -n "$REPO" ]]; then
  info "Cloning repository..."
  rm -rf "$INSTALL_DIR"
  git clone --depth 1 "$REPO" "$INSTALL_DIR"
  ok "Cloned to $INSTALL_DIR"
else
  if [[ -f "$PROJECT_DIR/go.mod" ]]; then
    if [[ "$PROJECT_DIR" != "$INSTALL_DIR" ]]; then
      info "Copying project to $INSTALL_DIR..."
      mkdir -p "$INSTALL_DIR"
      rsync -a --exclude '.git' --exclude '/spectra-server' --exclude '/spectra-client' \
            --exclude '*.exe' --exclude 'certs/' \
            "$PROJECT_DIR/" "$INSTALL_DIR/"
      ok "Copied to $INSTALL_DIR"
    else
      ok "Already in $INSTALL_DIR"
    fi
  else
    fatal "Cannot find project source. Run from the project root or pass --repo URL."
  fi
fi

# ─── Step 3: Build server ────────────────────────────────────────────────────
info "Building spectra-server..."
cd "$INSTALL_DIR"
export PATH=$PATH:/usr/local/go/bin
go build -ldflags="-s -w" -o spectra-server ./cmd/spectra-server
ok "Built: $INSTALL_DIR/spectra-server ($(./spectra-server --version 2>&1 || true))"

# ─── Step 4: Generate or validate PSK ────────────────────────────────────────
if [[ -z "$PSK" ]]; then
  PSK=$(openssl rand -hex 32)
  warn "No --psk provided, generated new PSK."
fi

if [[ ${#PSK} -ne 64 ]]; then
  fatal "PSK must be exactly 64 hex characters (32 bytes). Got ${#PSK} chars."
fi

# ─── Step 5: Copy certificates ───────────────────────────────────────────────
info "Setting up certificates..."
mkdir -p "$INSTALL_DIR/certs"
cp "$CERT" "$INSTALL_DIR/certs/cert.pem"
cp "$KEY"  "$INSTALL_DIR/certs/key.pem"
chmod 600 "$INSTALL_DIR/certs/key.pem"
ok "Certificates copied to $INSTALL_DIR/certs/"

# ─── Step 6: Apply sysctl tuning ─────────────────────────────────────────────
info "Applying QUIC UDP buffer tuning..."
if [[ -f "$INSTALL_DIR/deployments/sysctl/99-spectra-quic.conf" ]]; then
  cp "$INSTALL_DIR/deployments/sysctl/99-spectra-quic.conf" /etc/sysctl.d/99-spectra-quic.conf
  sysctl --system >/dev/null 2>&1
  ok "sysctl tuning applied"
else
  warn "sysctl config not found, skipping"
fi

# ─── Step 7: Create systemd service ──────────────────────────────────────────
info "Creating systemd service: ${SERVICE_NAME}..."
install -d -m 700 "$ENV_DIR"
ENV_FILE="${ENV_DIR}/${SERVICE_NAME}.env"
cat > "$ENV_FILE" <<ENV
SPECTRA_PSK="$(env_escape "$PSK")"
SPECTRA_CERT="$(env_escape "${INSTALL_DIR}/certs/cert.pem")"
SPECTRA_KEY="$(env_escape "${INSTALL_DIR}/certs/key.pem")"
SPECTRA_LISTEN="$(env_escape "$LISTEN")"
SPECTRA_PROFILE="$(env_escape "${INSTALL_DIR}/${PROFILE}")"
ENV
chmod 600 "$ENV_FILE"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=SPECTRA Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/spectra-server
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1
systemctl restart "${SERVICE_NAME}"
ok "Service ${SERVICE_NAME} started"

# ─── Step 8: Firewall ────────────────────────────────────────────────────────
PORT="${LISTEN#:}"
if command -v ufw &>/dev/null; then
  ufw allow "${PORT}/udp" >/dev/null 2>&1 || true
  ok "UFW: UDP ${PORT} allowed"
elif command -v firewall-cmd &>/dev/null; then
  firewall-cmd --permanent --add-port="${PORT}/udp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
  ok "firewalld: UDP ${PORT} allowed"
else
  warn "No firewall tool detected. Make sure UDP ${PORT} is open."
fi

# ─── Step 9: Detect domain / IP ──────────────────────────────────────────────
if [[ -z "$DOMAIN" ]]; then
  # Try to extract CN/SAN from certificate
  DOMAIN=$(openssl x509 -in "$INSTALL_DIR/certs/cert.pem" -noout -subject 2>/dev/null \
    | sed -n 's/.*CN\s*=\s*//p' | sed 's/\s*$//' || true)
fi
if [[ -z "$DOMAIN" ]]; then
  DOMAIN=$(hostname -I | awk '{print $1}')
fi

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║            Deployment Complete!                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Server is running.${NC} Check status:"
echo "  sudo systemctl status ${SERVICE_NAME}"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo ""
echo -e "${YELLOW}=== YOUR PSK (save this!) ===${NC}"
echo "  $PSK"
echo ""
echo -e "${CYAN}=== Ubuntu Desktop client service command ===${NC}"
echo "  ./scripts/client-service.sh install \\"
echo "    --server ${DOMAIN}:${PORT} \\"
echo "    --sni ${DOMAIN} \\"
echo "    --psk \"${PSK}\""
echo "  ./scripts/quic-tune.sh enable"
echo ""
echo -e "${CYAN}=== One-shot client command ===${NC}"
echo "  ./spectra-client --server ${DOMAIN}:${PORT} --sni ${DOMAIN} --psk \"${PSK}\""
echo ""
echo -e "${CYAN}=== Quick test (after starting client) ===${NC}"
echo "  curl --socks5 127.0.0.1:1080 https://ifconfig.me"
echo ""
