#!/usr/bin/env bash
# sh/schedule.sh - Blue Whale cron-ready scan automation.
#
# Runs a full scan, compresses results to a dated archive, and rotates
# old archives/logs older than MAX_AGE_DAYS.
#
# Usage:
#   bash sh/schedule.sh --target <url> [--profile <name>] [--output-dir <dir>]
#   crontab: 0 2 * * * bash /path/to/sh/schedule.sh --target https://example.com
#
# Environment:
#   WHALE_TARGET      Override target URL
#   MAX_AGE_DAYS      Days before old archives are purged (default: 30)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="${PROJECT_ROOT}/reports"
ARCHIVE_DIR="${PROJECT_ROOT}/data/archives"
LOG_DIR="${PROJECT_ROOT}/data/tmp"

TARGET="${WHALE_TARGET:-}"
PROFILE=""
OUTPUT_DIR="${REPORTS_DIR}"
MAX_AGE_DAYS="${MAX_AGE_DAYS:-30}"
MAX_LOG_MB=100

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)     TARGET="$2";     shift 2 ;;
    --profile)    PROFILE="$2";    shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "[schedule] Unknown arg: $1" >&2; exit 1 ;;
  esac
done

log()  { echo "[schedule][$(date +%T)] $*"; }
warn() { echo "[schedule][$(date +%T)] WARN: $*" >&2; }

if [[ -z "${TARGET}" ]]; then
  echo "[schedule] ERROR: --target is required." >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${ARCHIVE_DIR}" "${LOG_DIR}"

DATESTAMP="$(date +%Y%m%d_%H%M%S)"
SCAN_LOG="${LOG_DIR}/schedule_${DATESTAMP}.log"

log "Scheduled scan -> ${TARGET}  profile=${PROFILE:-default}"

# Build scan command
SCAN_CMD=("python" "${PROJECT_ROOT}/main.py" "scan" "--target" "${TARGET}" "--format" "html")
if [[ -n "${PROFILE}" ]]; then
  SCAN_CMD+=("--profile" "${PROFILE}")
fi

# Run scan, capturing output to log
log "Running: ${SCAN_CMD[*]}"
"${SCAN_CMD[@]}" 2>&1 | tee "${SCAN_LOG}" || {
  warn "Scan exited non-zero - partial results may exist."
}

# Archive results
log "Archiving reports -> ${ARCHIVE_DIR}/whale_${DATESTAMP}.tar.gz"
if [[ -d "${OUTPUT_DIR}" ]] && compgen -G "${OUTPUT_DIR}/*.html" >/dev/null 2>&1; then
  tar -czf "${ARCHIVE_DIR}/whale_${DATESTAMP}.tar.gz" \
    -C "$(dirname "${OUTPUT_DIR}")" "$(basename "${OUTPUT_DIR}")" \
    2>/dev/null || warn "Archive creation failed."
  # Remove archived HTML files to keep reports/ lean
  find "${OUTPUT_DIR}" -name "*.html" -mmin +1 -delete 2>/dev/null || true
fi

# Rotate old archives (older than MAX_AGE_DAYS)
log "Rotating archives older than ${MAX_AGE_DAYS} days..."
find "${ARCHIVE_DIR}" -name "*.tar.gz" -mtime "+${MAX_AGE_DAYS}" -delete 2>/dev/null || true

# Rotate scan logs when directory grows beyond MAX_LOG_MB
LOG_MB="$(du -sm "${LOG_DIR}" 2>/dev/null | cut -f1)"
if (( LOG_MB > MAX_LOG_MB )); then
  log "Log directory is ${LOG_MB}MB - purging logs older than ${MAX_AGE_DAYS} days..."
  find "${LOG_DIR}" -name "*.log" -mtime "+${MAX_AGE_DAYS}" -delete 2>/dev/null || true
fi

log "Schedule run complete."
