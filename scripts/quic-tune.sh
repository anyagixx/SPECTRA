#!/usr/bin/env bash
#
# SPECTRA QUIC UDP buffer tuning helper.
#
# Usage:
#   ./scripts/quic-tune.sh enable
#   ./scripts/quic-tune.sh disable
#   ./scripts/quic-tune.sh status
#   ./scripts/quic-tune.sh restart-client
#
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fatal() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SOURCE_CONF="${PROJECT_DIR}/deployments/sysctl/99-spectra-quic.conf"
TARGET_CONF="/etc/sysctl.d/99-spectra-quic.conf"
BASELINE_FILE="/var/lib/spectra/quic-tune.baseline"
SERVICE_NAME="spectra-client.service"

KEYS=(
  net.core.rmem_default
  net.core.rmem_max
  net.core.wmem_default
  net.core.wmem_max
  net.ipv4.udp_rmem_min
  net.ipv4.udp_wmem_min
)

usage() {
  cat <<USAGE
Usage: $0 <enable|disable|status|restart-client>

Commands:
  enable          Install persistent QUIC UDP buffer tuning and reload sysctl.
  disable         Remove persistent tuning, restore saved runtime values if present.
  status          Show installed config, current values, and client service state.
  restart-client  Restart the user spectra-client service if systemd user is available.
USAGE
}

sudo_cmd() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

systemctl_user_available() {
  systemctl --user show-environment >/dev/null 2>&1
}

restart_client_if_active() {
  if ! systemctl_user_available; then
    warn "systemd --user is not available in this session; skipped client restart."
    return 0
  fi

  if systemctl --user is-active --quiet "$SERVICE_NAME"; then
    systemctl --user restart "$SERVICE_NAME"
    ok "Restarted $SERVICE_NAME"
  else
    info "$SERVICE_NAME is not active; restart is not needed."
  fi
}

save_baseline() {
  if sudo_cmd test -f "$BASELINE_FILE"; then
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  for key in "${KEYS[@]}"; do
    if value="$(sysctl -n "$key" 2>/dev/null)"; then
      printf '%s=%s\n' "$key" "$value" >> "$tmp"
    fi
  done

  sudo_cmd install -d -m 700 "$(dirname "$BASELINE_FILE")"
  sudo_cmd install -m 600 "$tmp" "$BASELINE_FILE"
  rm -f "$tmp"
  ok "Saved current sysctl baseline to $BASELINE_FILE"
}

restore_baseline() {
  if ! sudo_cmd test -f "$BASELINE_FILE"; then
    warn "No saved baseline found. Persistent config was removed; runtime values may stay changed until reboot or manual sysctl adjustment."
    return 0
  fi

  info "Restoring saved sysctl baseline..."
  while IFS='=' read -r key value; do
    [[ -z "${key:-}" || -z "${value:-}" ]] && continue
    sudo_cmd sysctl -w "${key}=${value}" >/dev/null || true
  done < <(sudo_cmd cat "$BASELINE_FILE")
  sudo_cmd rm -f "$BASELINE_FILE"
  ok "Restored saved sysctl baseline"
}

show_status() {
  if [[ -f "$TARGET_CONF" ]]; then
    ok "Persistent config installed: $TARGET_CONF"
  else
    warn "Persistent config is not installed: $TARGET_CONF"
  fi

  echo ""
  echo "Current sysctl values:"
  for key in "${KEYS[@]}"; do
    if value="$(sysctl -n "$key" 2>/dev/null)"; then
      printf '  %-28s %s\n' "$key" "$value"
    else
      printf '  %-28s unavailable\n' "$key"
    fi
  done

  echo ""
  if systemctl_user_available; then
    systemctl --user --no-pager --lines=0 status "$SERVICE_NAME" || true
  else
    warn "systemd --user is not available in this session."
  fi
}

enable_tuning() {
  [[ -f "$SOURCE_CONF" ]] || fatal "Cannot find source config: $SOURCE_CONF"
  save_baseline
  sudo_cmd install -m 644 "$SOURCE_CONF" "$TARGET_CONF"
  sudo_cmd sysctl --system >/dev/null
  ok "QUIC tuning enabled"
  restart_client_if_active
}

disable_tuning() {
  sudo_cmd rm -f "$TARGET_CONF"
  sudo_cmd sysctl --system >/dev/null
  restore_baseline
  ok "QUIC tuning disabled"
  restart_client_if_active
}

command="${1:-}"
case "$command" in
  enable) enable_tuning ;;
  disable) disable_tuning ;;
  status) show_status ;;
  restart-client) restart_client_if_active ;;
  --help|-h|help|"") usage ;;
  *) fatal "Unknown command: $command" ;;
esac
