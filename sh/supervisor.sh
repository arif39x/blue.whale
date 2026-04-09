#!/usr/bin/env bash
# sh/supervisor.sh - Blue Whale engine crash-recovery supervisor.
#
# Manages the whale-engine subprocess lifecycle from outside Python.
# Watches for process exit, restarts up to MAX_RESTARTS times with
# exponential backoff.
#
# Usage:
#   bash sh/supervisor.sh [--target <url>] [--profile <name>] [--max-restarts N]
#
# Environment:
#   WHALE_TARGET   Target URL (required if --target not given)
#   WHALE_PROFILE  Scan profile (optional)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${PROJECT_ROOT}/bin"
ENGINE_BIN="${BIN_DIR}/whale-engine"

TARGET="${WHALE_TARGET:-}"
PROFILE="${WHALE_PROFILE:-}"
MAX_RESTARTS=5
RESTART_DELAY=2   # initial delay in seconds (doubles each retry)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)       TARGET="$2";        shift 2 ;;
    --profile)      PROFILE="$2";       shift 2 ;;
    --max-restarts) MAX_RESTARTS="$2";  shift 2 ;;
    *) echo "[supervisor] Unknown arg: $1" >&2; exit 1 ;;
  esac
done

log()  { echo "[supervisor][$(date +%T)] $*"; }
warn() { echo "[supervisor][$(date +%T)] WARN: $*" >&2; }
die()  { echo "[supervisor][$(date +%T)] FATAL: $*" >&2; exit 1; }

if [[ ! -x "${ENGINE_BIN}" ]]; then
  die "whale-engine binary not found: ${ENGINE_BIN}. Run 'python main.py bootstrap' first."
fi

# Build the Python scan command
_build_cmd() {
  local cmd=("python" "${PROJECT_ROOT}/main.py" "scan")
  if [[ -n "${TARGET}" ]]; then
    cmd+=("--target" "${TARGET}")
  fi
  if [[ -n "${PROFILE}" ]]; then
    cmd+=("--profile" "${PROFILE}")
  fi
  echo "${cmd[@]}"
}

# Trap SIGINT/SIGTERM to clean up child
CHILD_PID=""
_shutdown() {
  log "Shutdown signal received."
  if [[ -n "${CHILD_PID}" ]] && kill -0 "${CHILD_PID}" 2>/dev/null; then
    kill -TERM "${CHILD_PID}" 2>/dev/null || true
    sleep 2
    kill -0 "${CHILD_PID}" 2>/dev/null && kill -KILL "${CHILD_PID}" 2>/dev/null || true
  fi
  exit 0
}
trap '_shutdown' INT TERM

RESTARTS=0
DELAY="${RESTART_DELAY}"

while true; do
  log "Starting scan (attempt $((RESTARTS + 1))/${MAX_RESTARTS}) ..."

  CMD=($(_build_cmd))
  "${CMD[@]}" &
  CHILD_PID=$!

  wait "${CHILD_PID}" && RC=0 || RC=$?

  if [[ ${RC} -eq 0 ]]; then
    log "Scan completed successfully (exit 0)."
    exit 0
  fi

  RESTARTS=$((RESTARTS + 1))
  if [[ ${RESTARTS} -ge ${MAX_RESTARTS} ]]; then
    die "Engine failed ${MAX_RESTARTS} times - giving up."
  fi

  warn "Engine exited with code ${RC}. Restarting in ${DELAY}s... (${RESTARTS}/${MAX_RESTARTS})"
  sleep "${DELAY}"
  DELAY=$((DELAY * 2))
done
