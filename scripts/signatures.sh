#!/usr/bin/env bash
# Usage: ./scripts/signatures.sh FOLDER
# Reports which Authenticode certificate each Windows program in FOLDER claims
# to be signed by, and which programs carry no signature at all.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="python3"
fi

PYTHONPATH="$ROOT/src" exec "$PYTHON" -m static_triage.signatures "$@"
