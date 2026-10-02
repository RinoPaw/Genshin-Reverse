#!/usr/bin/env bash
set -euo pipefail

OUTPUT="inputs/7.1.0-global"
PYTHON="python3"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage:
  scripts/fetch-7.1-samples.sh [--output DIR] [--python PYTHON]

Fetch the pinned Genshin Impact 7.1.0 Global / Windows x64 executable and
metadata sample used by this repository. The Sophon manifest and both expected
SHA-256 hashes are fixed here so maintained workflows share one sample identity.
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

"$PYTHON" tools/fetch_sophon_targets.py \
  --manifest-url 'https://autopatchhk.yuanshen.com/client_app/sophon/manifests/cxhpq4g4rgg0/sMXGW2ll3Fuu/manifest_671e1a92a6cf53ff_8d4dfb34d2ee2cf64aae45a9b1ecf58d' \
  --chunk-prefix 'https://autopatchhk.yuanshen.com/client_app/sophon/chunks/cxhpq4g4rgg0/sMXGW2ll3Fuu' \
  --output "$OUTPUT" \
  --expected-exe-sha256 '08a3086d5f3fe695f01dab61efa42e442006b18e5e475b2520df356f6a073b7d' \
  --expected-metadata-sha256 '05ae04d7a91b91cc880217a56b0b01f3e67f845b06e894216654ec5d160e0da0'
