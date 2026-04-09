#!/usr/bin/env bash


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BIN_DIR="${PROJECT_ROOT}/bin"
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

_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *) die "Unsupported OS: $(uname -s)" ;;
  esac
}

_arch() {
  case "$(uname -m)" in
    x86_64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "Unsupported arch: $(uname -m)" ;;
  esac
}

OS="$(_os)"
ARCH="$(_arch)"

_already_have() {
  local bin="$1"
  if [[ "$FORCE" == "false" ]]; then
    if [[ -x "${BIN_DIR}/${bin}" ]] || command -v "$bin" &>/dev/null; then
      log "${bin} already available — skipping."
      return 0
    fi
  fi
  return 1
}

_download_github_release() {
  local tool="$1"    # e.g. nuclei
  local org="$2"     # e.g. projectdiscovery
  local pattern="$3" # e.g. nuclei_*_linux_amd64.zip
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  log "Fetching latest ${tool} release from github.com/${org}/${tool} …"
  local api_url="https://api.github.com/repos/${org}/${tool}/releases/latest"
  local release_url
  release_url="$(curl -fsSL "$api_url" \
    | grep "browser_download_url" \
    | grep -E "${pattern}" \
    | head -1 \
    | cut -d '"' -f4)"

  if [[ -z "$release_url" ]]; then
    log "WARNING: Could not resolve download URL for ${tool}. Install it manually."
    return 1
  fi

  local archive="${tmp_dir}/${tool}.archive"
  curl -fsSL -o "$archive" "$release_url"

  case "$release_url" in
    *.zip)    unzip -q "$archive" -d "$tmp_dir" ;;
    *.tar.gz) tar -xzf "$archive" -C "$tmp_dir" ;;
    *)        die "Unknown archive format: $release_url" ;;
  esac

  local extracted
  extracted="$(find "$tmp_dir" -maxdepth 2 -name "${tool}" -type f | head -1)"
  if [[ -z "$extracted" ]]; then
    log "WARNING: Binary '${tool}' not found in archive. Install manually."
    rm -rf "$tmp_dir"
    return 1
  fi

  install -m755 "$extracted" "${BIN_DIR}/${tool}"
  rm -rf "$tmp_dir"
  log "SUCCESS: ${tool} installed → ${BIN_DIR}/${tool}"
}

echo ""
echo "############################################"
echo "#           Blue Whale                     #"
echo "############################################"
echo ""

_already_have nuclei || _download_github_release \
  "nuclei" "projectdiscovery" "nuclei_.*_${OS}_${ARCH}.zip"

if command -v nuclei &>/dev/null; then
  log "Updating nuclei templates..."
  nuclei -ut -silent || warn "Nuclei template update failed"
fi

_already_have katana || _download_github_release \
  "katana" "projectdiscovery" "katana_.*_${OS}_${ARCH}.zip"

_already_have ffuf || _download_github_release \
  "ffuf" "ffuf" "ffuf_.*_${OS}_${ARCH}.tar.gz"

ENGINE_SRC="${PROJECT_ROOT}/engine"
ENGINE_BIN="${BIN_DIR}/whale-engine"

if [[ "$FORCE" == "false" && -x "$ENGINE_BIN" ]]; then
  log "whale-engine already built — skipping."
elif command -v go &>/dev/null; then
  log "Building whale-engine with Go…"
  (cd "$ENGINE_SRC" && go build -o "${ENGINE_BIN}" .)
  log "SUCCESS: whale-engine built → ${ENGINE_BIN}"
else
  log "WARNING: Go not found. whale-engine will not be available."
fi

# jq check
#
if command -v jq &>/dev/null; then
  log "SUCCESS: jq available: $(jq --version)"
else
  log "WARNING: jq not found. Install via: sudo apt install jq"
fi

echo ""
log "Bootstrap complete. Run 'python main.py --help' to start."
