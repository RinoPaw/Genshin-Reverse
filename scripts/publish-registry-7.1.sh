#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/publish-registry-7.1.sh [--work DIR] [--destination DIR] [--python PYTHON]

Prerequisites:
  1. scripts/regenerate-7.1.sh ... --astaps ../AstaPS
  2. scripts/close-registry-7.1.sh ... --require-direction-perfect

The default destination is inside work/, so running this command does not
silently overwrite committed version artifacts.
EOF
}

WORK="work/7.1.0-global/windows-x64"
DESTINATION=""
PYTHON="python3"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --destination) DESTINATION="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -z "$DESTINATION" ]]; then
  DESTINATION="$WORK/canonical-registry"
fi

REQUIRED=(
  "$WORK/registry-native-direct.csv"
  "$WORK/registry-native-usage.csv"
  "$WORK/registry-native-compare.json"
  "$WORK/registry-direction-audit.json"
  "$WORK/known-opcodes.csv"
  "$WORK/getcmdid-candidates.csv"
  "versions/7.1.0-global/windows-x64/hashes.json"
)
for required in "${REQUIRED[@]}"; do
  if [[ ! -f "$required" ]]; then
    echo "Required publication artifact is missing: $required" >&2
    echo "Run regeneration and strict registry closure first." >&2
    exit 1
  fi
done

"$PYTHON" -m genshinre.registrypublish \
  "$WORK/registry-native-direct.csv" \
  "$WORK/registry-native-usage.csv" \
  "$WORK/registry-native-compare.json" \
  "$WORK/registry-direction-audit.json" \
  "$WORK/known-opcodes.csv" \
  "$WORK/getcmdid-candidates.csv" \
  versions/7.1.0-global/windows-x64/hashes.json \
  "$DESTINATION"

printf 'Canonical registry publication gates passed.\n'
printf 'Output: %s\n' "$DESTINATION"
printf 'Review summary.json and the semantic-name gaps before committing generated artifacts.\n'
