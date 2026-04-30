#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${PROJECT_ROOT}/bin"
ENGINE_SRC="${PROJECT_ROOT}/src/engine"
ENGINE_BIN="${BIN_DIR}/whale-engine"
FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=true; shift ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "${BIN_DIR}"

log()  { echo "  [bootstrap] $*"; }
die()  { echo "  [bootstrap] FATAL: $*" >&2; exit 1; }
ok()   { echo "  [bootstrap] + $*"; }
warn() { echo "  [bootstrap] ! $*" >&2; }

echo ""
echo "╔══════════════════════════════════════╗"
echo "║              Blue Whale              ║"
echo "╚══════════════════════════════════════╝"
echo ""

if ! command -v go &>/dev/null; then
  die "Go is not installed. Install from https://go.dev/dl/ and retry."
fi
GO_VERSION="$(go version | awk '{print $3}')"
ok "Go found: ${GO_VERSION}"

log "Fetching Go dependencies (golang.org/x/net)..."
(cd "${ENGINE_SRC}" && go mod download && go mod tidy)
ok "Go dependencies resolved."

if [[ "${FORCE}" == "false" && -x "${ENGINE_BIN}" ]]; then
  ok "whale-engine already built - skipping (use --force to rebuild)."
else
  log "Building whale-engine..."
  (cd "${ENGINE_SRC}" && go build -o "${ENGINE_BIN}" .)
  chmod +x "${ENGINE_BIN}"
  ok "whale-engine built -> ${ENGINE_BIN}"
fi

"${ENGINE_BIN}" check && ok "whale-engine self-check passed."

BRAIN_SRC="${PROJECT_ROOT}/src/brain"
BRAIN_BIN="${BIN_DIR}/whale-brain"
if [[ "${FORCE}" == "false" && -x "${BRAIN_BIN}" ]]; then
  ok "whale-brain already built - skipping."
else
  if command -v cargo &>/dev/null; then
    log "Building whale-brain (Rust)..."
    (cd "${BRAIN_SRC}" && cargo build --release)
    cp "${BRAIN_SRC}/target/release/whale-brain" "${BRAIN_BIN}"
    chmod +x "${BRAIN_BIN}"
    ok "whale-brain built -> ${BRAIN_BIN}"
  else
    warn "Rust/Cargo not found. Skipping whale-brain build. LLM features will be disabled."
  fi
fi

VENV_DIR="${PROJECT_ROOT}/.venv"
if [[ ! -d "${VENV_DIR}" ]]; then
  log "Creating Python virtual environment at ${VENV_DIR}..."
  python3 -m venv "${VENV_DIR}"
fi

PYTHON="${VENV_DIR}/bin/python"
PIP="${VENV_DIR}/bin/pip"

log "Installing Python dependencies..."
"${PIP}" install --quiet --upgrade pip
"${PIP}" install --quiet -r "${PROJECT_ROOT}/requirements.txt"
ok "Python dependencies installed."

if command -v jq &>/dev/null; then
  ok "jq available: $(jq --version)"
else
  warn "jq not found - useful for debugging JSON output. Install: sudo apt install jq"
fi

mkdir -p "${PROJECT_ROOT}/data/tmp" \
         "${PROJECT_ROOT}/data/archives" \
         "${PROJECT_ROOT}/reports"
ok "Project directories created."

echo ""
log "Bootstrap complete. Run: python main.py --help"
echo ""
