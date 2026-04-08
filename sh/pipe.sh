#!/usr/bin/env bash

set -euo pipefail

TARGET=""
RPS=10
TIMEOUT=300
SEVERITY="critical,high,medium,low"
JOB_ID="$(date +%s)"
WORKDIR="/tmp/moriarty_${JOB_ID}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${PROJECT_ROOT}/bin"
CONFIG_FILE="${PROJECT_ROOT}/config/settings.yaml"

# Argument parsing
# ~~~~~~~~~~~~~~~~
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   TARGET="$2";    shift 2 ;;
    --rps)      RPS="$2";       shift 2 ;;
    --timeout)  TIMEOUT="$2";   shift 2 ;;
    --severity) SEVERITY="$2";  shift 2 ;;
    --job-id)   JOB_ID="$2";    shift 2 ;;
    --workdir)  WORKDIR="$2";   shift 2 ;;
    *) echo "[pipe.sh] Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo '[pipe.sh] ERROR: --target is required.' >&2
  exit 1
fi

log()  { echo "[pipe.sh][${JOB_ID}] $*" >&2; }
die()  { log "FATAL: $*"; exit 1; }
warn() { log "WARN: $*"; }

#Dependency Checking
#~~~~~~~~~~~~~~~~~~~
_check_bin() {
  local bin="$1"
  if command -v "${BIN_DIR}/${bin}" &>/dev/null; then
    echo "${BIN_DIR}/${bin}"
  elif command -v "$bin" &>/dev/null; then
    echo "$bin"
  else
    die "Binary not found: ${bin}. Run 'python main.py bootstrap' to install."
  fi
}

KATANA_BIN="$(_check_bin katana)"
NUCLEI_BIN="$(_check_bin nuclei)"
JQ_BIN="$(_check_bin jq)"

log "Using katana=${KATANA_BIN} nuclei=${NUCLEI_BIN} jq=${JQ_BIN}"

ulimit -n 65535 2>/dev/null && log "ulimit -n set to 65535" || warn "ulimit -n could not be set (may need root)"

mkdir -p "${WORKDIR}"
KATANA_OUT="${WORKDIR}/katana_urls.txt"
log "Workspace: ${WORKDIR}"

_cleanup() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    log "Pipeline exited with code ${exit_code}. Partial results may exist in ${WORKDIR}."
  fi
}
trap '_cleanup' EXIT

# Pipefail already set; this ensures mid-pipe errors are caught
_pipe_error() {
  die "A stage in the pipeline failed (see stderr). Aborting."
}
trap '_pipe_error' ERR

# Katana surface crawl / link discovery
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
log "Stage 1: Katana recon on ${TARGET}"

"${KATANA_BIN}" \
  --url "${TARGET}" \
  --depth 3 \
  --rate-limit "${RPS}" \
  --timeout "${TIMEOUT}" \
  --output "${KATANA_OUT}" \
  --silent \
  --no-color \
  2>>"${WORKDIR}/katana_stderr.log" || {
    warn "Katana exited non-zero — continuing with partial URL list"
  }

if [[ ! -s "${KATANA_OUT}" ]]; then
  log "Katana produced no URLs. Writing target URL directly."
  echo "${TARGET}" > "${KATANA_OUT}"
fi

URL_COUNT="$(wc -l < "${KATANA_OUT}")"
log "Stage 1 complete: ${URL_COUNT} URLs discovered."

#Nuclei vulnerability scan + jq noise filter
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
log "Stage 2: Nuclei scan (severity=${SEVERITY})"

# (jq filter) keep only essential fields, strip raw request/response blobs
# to reduce memory pressure on the Python consumer.
JQ_FILTER='
  select(.info.severity != null) |
  {
    "template-id":  ."template-id",
    "name":          .info.name,
    "severity":      .info.severity,
    "host":          .host,
    "matched-at":   ."matched-at",
    "status-code":  ."response" | if type == "object" then ."status-code" else null end,
    "request": {
      "method": (.request | split(" ")[0] // "GET"),
      "headers": {}
    },
    "timestamp":     .timestamp
  }
'

"${NUCLEI_BIN}" \
  --list "${KATANA_OUT}" \
  --severity "${SEVERITY}" \
  --rate-limit "${RPS}" \
  --timeout "${TIMEOUT}" \
  --json-output /dev/stdout \
  --silent \
  --no-color \
  2>>"${WORKDIR}/nuclei_stderr.log" \
| "${JQ_BIN}" --unbuffered -c "${JQ_FILTER}" 2>/dev/null

log "Stage 2 complete."
