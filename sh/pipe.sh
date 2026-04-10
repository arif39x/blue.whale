#!/usr/bin/env bash


set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENGINE_BIN="${PROJECT_ROOT}/bin/whale-engine"

if [[ ! -x "${ENGINE_BIN}" ]]; then
  echo "[pipe.sh] ERROR: whale-engine not found at ${ENGINE_BIN}" >&2
  echo "[pipe.sh]        Run 'python main.py bootstrap' to build it." >&2
  exit 1
fi

# Pass stdin directly to the engine and stream stdout
exec "${ENGINE_BIN}" serve
