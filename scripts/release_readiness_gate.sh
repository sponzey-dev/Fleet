#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
INCLUDE_MANUAL=0
INCLUDE_REGISTRY=0
VERIFY_MANUAL_REBOOT=0
RELEASE_PUBLIC_KEY="docs/release-signing-public.pem"
FLEET_DATA_DIR="${FLEET_DATA_DIR:-/var/lib/fleet}"
export FLEET_DATA_DIR

usage() {
  echo "usage: $0 [--include-manual] [--include-registry] [--verify-manual-reboot] [--release-public-key <path>]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --include-manual)
      INCLUDE_MANUAL=1
      shift
      ;;
    --include-registry)
      INCLUDE_REGISTRY=1
      shift
      ;;
    --verify-manual-reboot)
      VERIFY_MANUAL_REBOOT=1
      shift
      ;;
    --release-public-key)
      shift
      if [ "$#" -eq 0 ]; then
        usage
        exit 1
      fi
      RELEASE_PUBLIC_KEY="$1"
      shift
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

cd "$REPO_ROOT"

run() {
  echo "==> $*"
  "$@"
}

# Capture this smoke's output so a future CLI change cannot copy its one-time admin token into gate logs.
run_mvp_smoke() {
  echo "==> ./scripts/smoke_mvp.sh"
  if ! MVP_SMOKE_OUTPUT="$(./scripts/smoke_mvp.sh 2>&1)"; then
    if printf '%s\n' "$MVP_SMOKE_OUTPUT" | grep -qi 'admin token'; then
      echo "MVP smoke failed; output suppressed because it contained an admin token" >&2
    else
      printf '%s\n' "$MVP_SMOKE_OUTPUT" >&2
    fi
    return 1
  fi
  if printf '%s\n' "$MVP_SMOKE_OUTPUT" | grep -qi 'admin token'; then
    echo "MVP smoke output must not contain an admin token" >&2
    return 1
  fi
  printf '%s\n' "$MVP_SMOKE_OUTPUT"
}

require_linux_root() {
  if [ "$(uname -s)" != "Linux" ]; then
    echo "manual release checks require Linux; current host is $(uname -s)" >&2
    exit 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "manual release checks require root. Re-run with sudo." >&2
    exit 1
  fi
}

if [ "$INCLUDE_MANUAL" -eq 1 ]; then
  require_linux_root
  if [ "${FLEET_MANUAL_DISPOSABLE_CONFIRMATION:-}" != "YES" ]; then
    echo "set FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES only on a disposable Linux VM" >&2
    exit 1
  fi
  run ./scripts/manual_systemd_reboot_smoke.sh preflight
elif [ "$VERIFY_MANUAL_REBOOT" -eq 1 ]; then
  require_linux_root
fi

run cargo fmt --all --check
run cargo test --workspace
run cargo clippy --workspace --all-targets -- -D warnings
run npm test --workspace @sponzey/fleet
run npm test --workspace web-admin
run npm run typecheck --workspace web-admin
run ./scripts/npm_local_pack_smoke.sh
run ./scripts/npm_platform_local_install_smoke.sh
run ./scripts/npm_demo_smoke.sh
run_mvp_smoke
run ./scripts/smoke_immediate_dispatch.sh
run ./scripts/smoke_remote_tls_loopback.sh
run ./scripts/signature_verification_smoke.sh
run sh ./scripts/storage_decision_gate.sh
if [ -f dist/release/SHA256SUMS ]; then
  run ./scripts/verify_standalone_artifacts.sh dist/release
else
  echo "standalone artifact verification skipped: dist/release/SHA256SUMS not found."
fi
if [ -f dist/release/SHA256SUMS.sig ]; then
  if [ ! -f "$RELEASE_PUBLIC_KEY" ]; then
    echo "release signature found but public key not found: $RELEASE_PUBLIC_KEY" >&2
    echo "Pass --release-public-key <path> with the pinned release public key." >&2
    exit 1
  fi
  run ./scripts/verify_release_signature.sh dist/release "$RELEASE_PUBLIC_KEY"
else
  echo "release signature verification skipped: dist/release/SHA256SUMS.sig not found."
fi
if [ -f target/release/fleet ]; then
  run ./scripts/check_linux_glibc_baseline.sh target/release/fleet
else
  echo "glibc baseline check skipped: target/release/fleet not built."
fi
run ./scripts/hardening_audit.sh
run node ./scripts/test_catalog_performance_gate.js
run python3 -m unittest scripts/test_manual_task_recovery_smoke.py

if [ "$INCLUDE_REGISTRY" -eq 1 ]; then
  run ./scripts/manual_npm_registry_smoke.sh
else
  echo "registry install check skipped."
  echo "After npm registry publish, run:"
  echo "  ./scripts/release_readiness_gate.sh --include-registry"
fi

if [ "$VERIFY_MANUAL_REBOOT" -eq 1 ]; then
  run ./scripts/manual_systemd_reboot_smoke.sh verify
  run python3 scripts/manual_task_recovery_smoke.py verify-reboot
elif [ "$INCLUDE_MANUAL" -eq 1 ]; then
  run ./scripts/manual_linux_nginx_runbook_smoke.sh
  run ./scripts/manual_systemd_reboot_smoke.sh install
  echo "manual service install completed. Run these recovery checks before reboot:"
  echo "  sudo env FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES FLEET_DATA_DIR=$FLEET_DATA_DIR python3 scripts/manual_task_recovery_smoke.py controller-restart"
  echo "  sudo env FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES FLEET_DATA_DIR=$FLEET_DATA_DIR python3 scripts/manual_task_recovery_smoke.py agent-restart"
  echo "  sudo env FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES FLEET_DATA_DIR=$FLEET_DATA_DIR python3 scripts/manual_task_recovery_smoke.py prepare-reboot"
  echo "Then reboot manually and verify:"
  echo "  sudo env FLEET_DATA_DIR=$FLEET_DATA_DIR ./scripts/release_readiness_gate.sh --verify-manual-reboot"
else
  echo "manual checks skipped."
  echo "To include destructive Linux checks, run:"
  echo "  sudo env FLEET_MANUAL_DISPOSABLE_CONFIRMATION=YES FLEET_DATA_DIR=/var/lib/fleet-task056 ./scripts/release_readiness_gate.sh --include-manual"
fi

echo "release readiness gate ok"
