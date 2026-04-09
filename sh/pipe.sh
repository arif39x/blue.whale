#!/usr/bin/env bash

set -euo pipefail

TARGET=""
HEADER=""
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
RPS=10
TIMEOUT=300
SEVERITY="critical,high,medium,low"
JOB_ID="$(date +%s)"
WORKDIR="/tmp/whale_${JOB_ID}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${PROJECT_ROOT}/bin"
DATA_DIR="${PROJECT_ROOT}/data"
CONFIG_FILE="${PROJECT_ROOT}/config/settings.yaml"

# Argument parsing
# ~~~~~~~~~~~~~~~~
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   TARGET="$2";    shift 2 ;;
    --rps)      RPS="$2";       shift 2 ;;
    --header)   HEADER="$2";    shift 2 ;;
    --timeout)  TIMEOUT="$2";   shift 2 ;;
    --severity) SEVERITY="$2";  shift 2 ;;
    --ua)       UA="$2";        shift 2 ;;
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
FFUF_BIN="$(_check_bin ffuf)"

log "Using katana=${KATANA_BIN} nuclei=${NUCLEI_BIN} jq=${JQ_BIN} ffuf=${FFUF_BIN}"

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

KATANA_CMD=("${KATANA_BIN}" "--url" "${TARGET}" "--depth" "3" "--rate-limit" "${RPS}" "--timeout" "${TIMEOUT}" "--output" "${KATANA_OUT}" "--silent" "--no-color" "-H" "User-Agent: ${UA}")
if [[ -n "${HEADER:-}" ]]; then
  KATANA_CMD+=("-H" "${HEADER}")
fi

"${KATANA_CMD[@]}" 2>>"${WORKDIR}/katana_stderr.log" || {
  warn "Katana exited non-zero — continuing with partial URL list"
}

if [[ ! -s "${KATANA_OUT}" ]]; then
  log "Katana produced no URLs. Writing target URL directly."
  echo "${TARGET}" > "${KATANA_OUT}"
fi

# Stage 1.5: FFUF Activation & Environmental Awareness
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
log "Stage 1.5: FFUF path discovery on ${TARGET}"

WORDLIST_DIR="${DATA_DIR}/wordlists"
WORDLIST_FILE="${WORDLIST_DIR}/dicc.txt"
if [[ ! -f "${WORDLIST_FILE}" ]]; then
  log "Wordlist not found at ${WORDLIST_FILE}. Downloading..."
  mkdir -p "${WORDLIST_DIR}"
  curl -fsSL "https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt" -o "${WORDLIST_FILE}" || warn "Wordlist download failed"
fi

FFUF_OUT="${WORKDIR}/ffuf.json"
FFUF_CMD=("${FFUF_BIN}" "-u" "${TARGET}/FUZZ" "-w" "${WORDLIST_FILE}" "-mc" "200,204,301,302,303,401,403" "-o" "${FFUF_OUT}" "-silent" "-H" "User-Agent: ${UA}")
if [[ -n "${HEADER:-}" ]]; then
  FFUF_CMD+=("-H" "${HEADER}")
fi

if [[ -f "${WORDLIST_FILE}" ]]; then
  "${FFUF_CMD[@]}" 2>>"${WORKDIR}/ffuf_stderr.log" || warn "ffuf exited non-zero — continuing"
fi

if [[ -s "${FFUF_OUT}" ]]; then
  "${JQ_BIN}" -r '.results[] | .url' "${FFUF_OUT}" 2>/dev/null >> "${KATANA_OUT}" || true
  sort -u "${KATANA_OUT}" -o "${KATANA_OUT}"
fi

URL_COUNT="$(wc -l < "${KATANA_OUT}")"
log "Stage 1 complete: ${URL_COUNT} URLs discovered."

#Nuclei vulnerability scan + jq noise filter
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
log "Stage 2: Nuclei scan (severity=${SEVERITY})"

# (jq filter) keep only essential fields, strip raw request/response blobs
# to reduce memory pressure on the Python consumer.
JQ_FILTER='
  select(.["template-id"] != null or .template != null) |
  {
    "template-id":  (."template-id" // .template // "unknown"),
    "name":          (.info.name // .template // "finding"),
    "severity":      (.info.severity // "info"),
    "host":          (.host // .url // "unknown"),
    "matched-at":   (."matched-at" // .url // "unknown"),
    "status-code":  (if .["status-code"] then .["status-code"] elif .response and type == "object" then .response["status-code"] else null end),
    "request": {
      "method": ((.request // "GET") | split(" ")[0]),
      "headers": {}
    },
    "timestamp":     (.timestamp // now | tostring)
  }
'

NUCLEI_CMD=("${NUCLEI_BIN}" "--list" "${KATANA_OUT}" "--severity" "${SEVERITY}" "--rate-limit" "${RPS}" "--timeout" "${TIMEOUT}" "--json-output" "/dev/stdout" "--silent" "--no-color" "-iserver" "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me" "-H" "User-Agent: ${UA}")
if [[ -n "${HEADER:-}" ]]; then
  NUCLEI_CMD+=("-H" "${HEADER}")
fi

"${NUCLEI_CMD[@]}" 2>>"${WORKDIR}/nuclei_stderr.log" \
| "${JQ_BIN}" --unbuffered -c "${JQ_FILTER}" 2>"${WORKDIR}/jq_stderr.log" || warn "Nuclei/jq pipeline failed or returned no results"

# Feedback for CLI/GUI users (STDOUT messages handled as special JSON by orchestrator if desired)
# For now, just echo progress to stderr for the executor logging.
echo '{"type":"progress","stage":"complete","findings":true}'

# Special debug check if zero findings
if [[ ! -s "${WORKDIR}/nuclei_stderr.log" ]] && [[ ! -s "${WORKDIR}/katana_urls.txt" ]]; then
  warn "No URLs found and no stderr recorded. Check connectivity."
fi

# Send explicit end-of-stage marker for UI
echo '{"type":"status","stage":"finished","job_id":"'${JOB_ID}'"}'

log "Stage 2 complete."
