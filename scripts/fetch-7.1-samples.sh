#!/usr/bin/env bash
set -euo pipefail

OUTPUT="inputs/7.1.0-global"
PYTHON="python3"
PROFILE="7.1.0-global/windows-x64"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage:
  scripts/fetch-7.1-samples.sh [--output DIR] [--python PYTHON]

Fetch the pinned Genshin Impact 7.1.0 Global / Windows x64 executable and
metadata sample used by this repository. The exact Sophon source and expected
hashes come from the maintained native profile.
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

"$PYTHON" -m genshinre.samplefetch \
  --profile "$PROFILE" \
  --output "$OUTPUT"
