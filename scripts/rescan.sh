#!/usr/bin/env bash
# Scan only the files you name, each with the whole stage budget.
#
#   ./scripts/rescan.sh ~/games/DontStarve bin/steam_api.dll
#   ./scripts/rescan.sh ~/games/DontStarve 'bin/steam*.dll' bin/Steam.dll
#
# A file that timed out in a full scan gets far longer here, because
# nothing else is competing for the budget or the memory.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 FOLDER PATH [PATH...]" >&2
  echo "       PATH is relative to FOLDER, as the report writes it" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
exec python3 -m static_triage.cli rescan "$@"
