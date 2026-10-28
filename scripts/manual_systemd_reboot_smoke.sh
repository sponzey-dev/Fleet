#!/usr/bin/env sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
  echo "manual systemd reboot smoke requires Linux" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "manual systemd reboot smoke requires root. Re-run with sudo." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "manual systemd reboot smoke requires systemd/systemctl" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "manual systemd reboot smoke requires curl" >&2
  exit 1
fi

BIN="${FLEET_BIN:-./target/debug/fleet}"
DATA_DIR="${FLEET_DATA_DIR:-/var/lib/fleet}"
CONTROLLER_URL="${FLEET_CONTROLLER_URL:-http://127.0.0.1:7700}"
MODE="${1:-install}"

check_install_target() {
  if [ "${FLEET_MANUAL_DISPOSABLE_CONFIRMATION:-}" != "YES" ]; then
    echo "set FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES only for a disposable Linux VM" >&2
    exit 1
  fi
  case "$DATA_DIR" in
    /*) ;;
    *)
      echo "FLEET_DATA_DIR must be an absolute path" >&2
      exit 1
      ;;
  esac
  if [ "$DATA_DIR" = "/" ] || [ -L "$DATA_DIR" ]; then
    echo "refusing root or symlink FLEET_DATA_DIR: $DATA_DIR" >&2
    exit 1
  fi
  if [ -e "$DATA_DIR" ] && [ ! -d "$DATA_DIR" ]; then
    echo "FLEET_DATA_DIR exists but is not a directory: $DATA_DIR" >&2
    exit 1
  fi
  if [ -d "$DATA_DIR" ] && [ -n "$(find "$DATA_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "refusing non-empty FLEET_DATA_DIR: $DATA_DIR" >&2
    exit 1
  fi
  for unit in fleet-controller.service fleet-agent.service; do
    if systemctl cat "$unit" >/dev/null 2>&1; then
      echo "refusing to overwrite existing systemd unit: $unit" >&2
      exit 1
    fi
  done
}

case "$MODE" in
  preflight)
    check_install_target
    echo "manual systemd smoke preflight ok for $DATA_DIR"
    ;;
  install)
    check_install_target
    cargo build -p fleet-cli
    case "$-" in
      *x*) set +x ;;
    esac
    INIT_OUTPUT="$("$BIN" controller init --data-dir "$DATA_DIR")"
    ADMIN_TOKEN="$(printf '%s\n' "$INIT_OUTPUT" | sed -n 's/^admin token: //p' | sed '/^already initialized$/d')"
    printf '%s\n' "$INIT_OUTPUT" | sed '/^admin token:/d'
    if [ -n "$ADMIN_TOKEN" ]; then
      printf 'one-time admin token for recovery smoke (store securely): %s\n' "$ADMIN_TOKEN"
    else
      echo "controller was already initialized; provide its existing admin token to the recovery smoke"
    fi
    unset ADMIN_TOKEN INIT_OUTPUT
    TOKEN="$("$BIN" enroll-token create --data-dir "$DATA_DIR" --labels role=local,env=manual)"
    "$BIN" controller install-service --data-dir "$DATA_DIR"
    "$BIN" agent install-service --data-dir "$DATA_DIR"
    "$BIN" controller start-service
    i=0
    while [ "$i" -lt 50 ]; do
      if curl -fsS "$CONTROLLER_URL/healthz" >/dev/null 2>&1; then
        break
      fi
      i=$((i + 1))
      sleep 0.2
    done
    if [ "$i" -eq 50 ]; then
      echo "controller service did not become healthy at $CONTROLLER_URL" >&2
      exit 1
    fi
    "$BIN" agent init \
      --data-dir "$DATA_DIR" \
      --url "$CONTROLLER_URL" \
      --token "$TOKEN" \
      --name local-agent \
      --labels role=local,env=manual
    "$BIN" agent start-service
    systemctl is-enabled fleet-controller.service >/dev/null
    systemctl is-enabled fleet-agent.service >/dev/null
    systemctl is-active fleet-controller.service >/dev/null
    systemctl is-active fleet-agent.service >/dev/null
    echo "services installed and active. Reboot this host, then run:"
    echo "  sudo $0 verify"
    ;;
  verify)
    systemctl is-enabled fleet-controller.service >/dev/null
    systemctl is-enabled fleet-agent.service >/dev/null
    systemctl is-active fleet-controller.service >/dev/null
    systemctl is-active fleet-agent.service >/dev/null
    echo "manual systemd reboot smoke ok"
    ;;
  *)
    echo "usage: $0 [preflight|install|verify]" >&2
    exit 1
    ;;
esac
