#!/usr/bin/env bash
#
# SPECTRA client user-service manager for Ubuntu Desktop.
#
# Usage:
#   ./scripts/client-service.sh install --server example.com:443 --sni example.com --psk HEX
#   ./scripts/client-service.sh status
#   ./scripts/client-service.sh logs
#   ./scripts/client-service.sh restart
#   ./scripts/client-service.sh uninstall
#
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fatal() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SERVICE_NAME="spectra-client"
UNIT_DIR="${HOME}/.config/systemd/user"
UNIT_FILE="${UNIT_DIR}/${SERVICE_NAME}.service"
CONFIG_DIR="${HOME}/.config/spectra"
ENV_FILE="${CONFIG_DIR}/client.env"
GO_VERSION="1.22.5"

SERVER=""
PSK=""
SNI=""
SOCKS="127.0.0.1:1080"
PROFILE="${PROJECT_DIR}/configs/profiles/geforcenow.json"
INSECURE=""

usage() {
  cat <<USAGE
Usage: $0 <command> [options]

Commands:
  install --server HOST:PORT --psk HEX [--sni DOMAIN] [--socks ADDR] [--profile PATH] [--insecure]
  start
  stop
  restart
  status
  logs
  uninstall [--purge]

The install command builds spectra-client, stores client settings in:
  $ENV_FILE
and creates a user systemd service:
  $UNIT_FILE
USAGE
}

install_packages() {
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

systemctl_user_available() {
  systemctl --user show-environment >/dev/null 2>&1
}

require_systemctl_user() {
  if ! systemctl_user_available; then
    fatal "systemd --user is not available. Run this from an interactive Ubuntu Desktop session."
  fi
}

ensure_go() {
  export PATH="$PATH:/usr/local/go/bin"
  if command -v go &>/dev/null; then
    ok "Go already installed: $(go version)"
    return 0
  fi

  info "Go not found. Installing Go ${GO_VERSION}..."
  ensure_downloader
  ensure_command tar
  local go_tar="go${GO_VERSION}.linux-amd64.tar.gz"
  download_file "https://go.dev/dl/${go_tar}" "/tmp/${go_tar}"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "/tmp/${go_tar}"
  rm -f "/tmp/${go_tar}"
  export PATH="$PATH:/usr/local/go/bin"
  if [[ ! -f /etc/profile.d/go.sh ]] || ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh; then
    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
  fi
  ok "Go installed: $(go version)"
}

build_client() {
  [[ -f "${PROJECT_DIR}/go.mod" ]] || fatal "Cannot find project root: $PROJECT_DIR"
  ensure_go
  info "Building spectra-client..."
  (cd "$PROJECT_DIR" && go build -ldflags="-s -w" -o spectra-client ./cmd/spectra-client)
  ok "Built ${PROJECT_DIR}/spectra-client"
}

derive_sni() {
  local host="$SERVER"
  if [[ "$host" == \[*\]:* ]]; then
    host="${host#\[}"
    host="${host%%\]*}"
  else
    host="${host%%:*}"
  fi
  printf '%s' "$host"
}

parse_install_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server) SERVER="$2"; shift 2 ;;
      --psk) PSK="$2"; shift 2 ;;
      --sni) SNI="$2"; shift 2 ;;
      --socks) SOCKS="$2"; shift 2 ;;
      --profile) PROFILE="$2"; shift 2 ;;
      --insecure) INSECURE="1"; shift ;;
      --help|-h) usage; exit 0 ;;
      *) fatal "Unknown install option: $1" ;;
    esac
  done

  [[ -n "$SERVER" ]] || fatal "--server HOST:PORT is required"
  [[ -n "$PSK" ]] || fatal "--psk HEX is required"
  [[ ${#PSK} -eq 64 ]] || fatal "PSK must be exactly 64 hex characters. Got ${#PSK}."
  [[ -n "$SNI" ]] || SNI="$(derive_sni)"
  [[ -f "$PROFILE" ]] || fatal "Profile file not found: $PROFILE"
}

write_env_file() {
  install -d -m 700 "$CONFIG_DIR"
  cat > "$ENV_FILE" <<ENV
SPECTRA_BIN="$(env_escape "${PROJECT_DIR}/spectra-client")"
SPECTRA_SERVER="$(env_escape "$SERVER")"
SPECTRA_SNI="$(env_escape "$SNI")"
SPECTRA_PSK="$(env_escape "$PSK")"
SPECTRA_SOCKS_LISTEN="$(env_escape "$SOCKS")"
SPECTRA_PROFILE="$(env_escape "$PROFILE")"
SPECTRA_INSECURE="$(env_escape "$INSECURE")"
ENV
  chmod 600 "$ENV_FILE"
  ok "Wrote client config to $ENV_FILE"
}

write_unit_file() {
  install -d -m 700 "$UNIT_DIR"
  cat > "$UNIT_FILE" <<UNIT
[Unit]
Description=SPECTRA Proxy Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=/bin/sh -c 'exec "\$SPECTRA_BIN" \${SPECTRA_INSECURE:+--insecure}'
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=default.target
UNIT
  ok "Wrote user service to $UNIT_FILE"
}

install_service() {
  parse_install_args "$@"
  require_systemctl_user
  build_client
  write_env_file
  write_unit_file
  systemctl --user daemon-reload
  systemctl --user enable --now "$SERVICE_NAME" >/dev/null
  ok "Started $SERVICE_NAME"
  echo ""
  echo "Test:"
  echo "  curl --socks5-hostname ${SOCKS} https://ifconfig.me/ip"
}

service_command() {
  require_systemctl_user
  local command="$1"
  case "$command" in
    start|stop|restart)
      systemctl --user "$command" "$SERVICE_NAME"
      ;;
    status)
      systemctl --user --no-pager --lines=30 status "$SERVICE_NAME" || true
      ;;
    logs)
      journalctl --user -u "$SERVICE_NAME" -f
      ;;
    *)
      fatal "Unsupported service command: $command"
      ;;
  esac
}

uninstall_service() {
  require_systemctl_user
  local purge=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge) purge="1"; shift ;;
      *) fatal "Unknown uninstall option: $1" ;;
    esac
  done

  systemctl --user disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE"
  systemctl --user daemon-reload
  if [[ -n "$purge" ]]; then
    rm -f "$ENV_FILE"
    rmdir "$CONFIG_DIR" 2>/dev/null || true
  fi
  ok "Uninstalled $SERVICE_NAME"
}

command="${1:-}"
[[ -n "$command" ]] || { usage; exit 0; }
shift || true

case "$command" in
  install) install_service "$@" ;;
  start|stop|restart|status|logs) service_command "$command" ;;
  uninstall) uninstall_service "$@" ;;
  --help|-h|help) usage ;;
  *) fatal "Unknown command: $command" ;;
esac
