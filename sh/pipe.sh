#!/usr/bin/env bash
# sh/pipe.sh - Legacy shim (retained for compatibility).
#
# The primary scan pipeline is now driven by the Python bridge (core/bridge.py)
# which communicates directly with whale-engine via JSON-RPC over stdin/stdout.
#
# This script is no longer part of the main scan flow. It is kept as a utility
# shim for debugging raw engine interactions from the shell.
#
# Usage:
#   echo '{"type":"scan_start","targets":["https://example.com"],"config":{"workers":5,"max_depth":2}}' \
#     | bash sh/pipe.sh

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
