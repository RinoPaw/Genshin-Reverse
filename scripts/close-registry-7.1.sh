#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/close-registry-7.1.sh --exe PATH [--output DIR] [--python PYTHON] [--require-direction-perfect]

Historical native-layout reproduction helper. Run scripts/regenerate-7.1.sh
first. This command intentionally fails unless both independent native layout
paths close and agree across all 4,896 rows.

If control-set.csv exists, registry_flag semantics are also audited against
independent Req/Rsp controls. Pass --require-direction-perfect to make that
audit a hard gate for the historical native-layout projection.

This command does not publish the current canonical registry; the maintained
canonical identity publisher is genshinre.registryxrefpublish.
EOF
}

EXE=""
OUTPUT="work/7.1.0-global/windows-x64"
PYTHON="python3"
REQUIRE_DIRECTION_PERFECT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exe) EXE="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    --require-direction-perfect) REQUIRE_DIRECTION_PERFECT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$EXE" ]]; then
  usage >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

for required in \
  "$OUTPUT/registry-layout-probe.json" \
  "$OUTPUT/registry-usage-layout-probe.json" \
  "$OUTPUT/metadata-usage-types.csv"; do
  if [[ ! -f "$required" ]]; then
    echo "Required regeneration artifact is missing: $required" >&2
    echo "Run scripts/regenerate-7.1.sh first." >&2
    exit 1
  fi
done

printf '[historical 1/4] Exporting direct-slot native registry rows\n'
"$PYTHON" -m genshinre.registryraw \
  "$EXE" \
  "$OUTPUT/registry-layout-probe.json" \
  "$OUTPUT/registry-native-direct.csv" \
  --summary "$OUTPUT/registry-native-direct.summary.json" \
  --require-4896-unique \
  > /dev/null

printf '[historical 2/4] Exporting usage-backed native registry rows\n'
"$PYTHON" -m genshinre.registryusageraw \
  "$EXE" \
  "$OUTPUT/registry-usage-layout-probe.json" \
  "$OUTPUT/metadata-usage-types.csv" \
  "$OUTPUT/registry-native-usage.csv" \
  --summary "$OUTPUT/registry-native-usage.summary.json" \
  --require-4896-unique \
  > /dev/null

printf '[historical 3/4] Requiring independent row-by-row agreement\n'
"$PYTHON" -m genshinre.registrycompare \
  "$OUTPUT/registry-native-direct.csv" \
  "$OUTPUT/registry-native-usage.csv" \
  --output "$OUTPUT/registry-native-compare.json" \
  --require-full-agreement \
  > /dev/null

printf '[historical 4/4] Auditing registry_flag direction semantics\n'
if [[ -f "$OUTPUT/control-set.csv" ]]; then
  DIRECTION_ARGS=(
    -m genshinre.directionaudit
    "$OUTPUT/registry-native-usage.csv"
    "$OUTPUT/control-set.csv"
    --output "$OUTPUT/registry-direction-audit.json"
  )
  if [[ "$REQUIRE_DIRECTION_PERFECT" -eq 1 ]]; then
    DIRECTION_ARGS+=(--require-perfect)
  fi
  "$PYTHON" "${DIRECTION_ARGS[@]}" > /dev/null
else
  if [[ "$REQUIRE_DIRECTION_PERFECT" -eq 1 ]]; then
    echo "control-set.csv is required by --require-direction-perfect; rerun regeneration with --astaps DIR" >&2
    exit 1
  fi
  echo '      skipped; control-set.csv was not generated (pass --astaps DIR to regenerate-7.1.sh)'
fi

printf 'Historical native registry structural closure passed.\n'
printf 'Direct raw: %s\n' "$OUTPUT/registry-native-direct.csv"
printf 'Usage raw:  %s\n' "$OUTPUT/registry-native-usage.csv"
printf 'Comparison: %s\n' "$OUTPUT/registry-native-compare.json"
if [[ -f "$OUTPUT/registry-direction-audit.json" ]]; then
  printf 'Direction audit: %s\n' "$OUTPUT/registry-direction-audit.json"
fi
printf 'These artifacts are historical/native-layout evidence; do not overwrite the xref-published canonical registry with them.\n'
