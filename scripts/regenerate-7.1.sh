#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/regenerate-7.1.sh --exe PATH --metadata PATH [--output DIR] [--python PYTHON] [--astaps DIR]

The exact-sample metadata/runtime/GetCmdId stages are required. Research stages
may remain unresolved, but no alternate recovery path is substituted when a
stage fails.
EOF
}

EXE=""
METADATA=""
OUTPUT="work/7.1.0-global/windows-x64"
PYTHON="python3"
ASTAPS=""
OPTIONAL_FAILURES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exe) EXE="$2"; shift 2 ;;
    --metadata) METADATA="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    --astaps) ASTAPS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$EXE" || -z "$METADATA" ]]; then
  usage >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
mkdir -p "$OUTPUT/metadata"

optional_failure() {
  OPTIONAL_FAILURES+=("$1")
  printf '      optional stage failed: %s\n' "$1" >&2
}

printf '[core 1/5] Fingerprinting exact samples\n'
"$PYTHON" -m genshinre fingerprint "$EXE" "$METADATA" > "$OUTPUT/fingerprints.json"

printf '[core 2/5] Decoding native 7.1 MHY metadata\n'
"$PYTHON" -m genshinre decode-metadata-71 "$EXE" "$METADATA" "$OUTPUT/metadata"

printf '[core 3/5] Verifying full 7.1 metadata anchors\n'
"$PYTHON" -m genshinre verify-metadata \
  "$OUTPUT/metadata" \
  versions/7.1.0-global/windows-x64/metadata/anchors.json \
  > "$OUTPUT/metadata-anchor-check.json"

printf '[core 4/5] Exporting IL2CPP runtime type index\n'
"$PYTHON" -m genshinre.typearray \
  "$EXE" \
  "$OUTPUT/metadata/types.csv" \
  "$OUTPUT/metadata/runtime-types.csv" \
  --summary "$OUTPUT/metadata/runtime-types.summary.json" \
  > /dev/null

printf '[core 5/5] Scanning conservative constant-return CmdId candidates\n'
"$PYTHON" -m genshinre scan-constant-cmdids \
  "$EXE" \
  "$OUTPUT/metadata/methods.csv" \
  "$OUTPUT/getcmdid-candidates.csv" \
  --summary "$OUTPUT/getcmdid-candidates.summary.json"

printf '[optional 1/11] Auditing metadata-usage initializer call sites\n'
if ! "$PYTHON" -m genshinre.usage \
  "$EXE" \
  "$OUTPUT/metadata-usage-sites.csv" \
  --summary "$OUTPUT/metadata-usage-sites.summary.json" \
  > /dev/null; then
  optional_failure metadata-usage-sites
fi

printf '[optional 2/11] Probing metadata registration structure\n'
if ! "$PYTHON" -m genshinre.metareg \
  "$EXE" \
  "$OUTPUT/metadata-registration-probe.json" \
  > /dev/null; then
  optional_failure metadata-registration-probe
fi

printf '[optional 3/11] Recovering metadata usage destination table\n'
usage_slots_ok=false
if "$PYTHON" -m genshinre.metausage \
  "$EXE" \
  "$OUTPUT/metadata-usage-slots.csv" \
  --summary "$OUTPUT/metadata-usage-slots.summary.json" \
  > /dev/null; then
  usage_slots_ok=true
else
  optional_failure metadata-usage-table
fi

printf '[optional 4/11] Joining metadata usages to runtime types\n'
usage_types_ok=false
if [[ "$usage_slots_ok" == true ]]; then
  if "$PYTHON" -m genshinre.usagejoin \
    "$EXE" \
    "$OUTPUT/metadata-usage-slots.csv" \
    "$OUTPUT/metadata/runtime-types.csv" \
    "$OUTPUT/metadata-usage-types.csv" \
    --summary "$OUTPUT/metadata-usage-types.summary.json" \
    > /dev/null; then
    usage_types_ok=true
  else
    optional_failure metadata-usage-type-join
  fi
else
  echo '      skipped; metadata usage slots unavailable'
fi

printf '[optional 5/11] Building registry candidate graph\n'
graph_ok=false
if [[ "$usage_types_ok" == true ]]; then
  if "$PYTHON" -m genshinre.registrygraph \
    "$OUTPUT/metadata-usage-types.csv" \
    "$OUTPUT/getcmdid-candidates.csv" \
    "$OUTPUT/registry-candidate-graph.csv" \
    --summary "$OUTPUT/registry-candidate-graph.summary.json" \
    > /dev/null; then
    graph_ok=true
  else
    optional_failure registry-candidate-graph
  fi
else
  echo '      skipped; metadata usage/type join unavailable'
fi

printf '[optional 6/11] Refining one-to-one static registry candidates\n'
static_candidates_ok=false
if [[ "$graph_ok" == true ]]; then
  if "$PYTHON" -m genshinre.registryselect \
    "$OUTPUT/registry-candidate-graph.csv" \
    "$OUTPUT/registry-static-candidates.csv" \
    --summary "$OUTPUT/registry-static-candidates.summary.json" \
    > /dev/null; then
    static_candidates_ok=true
  else
    optional_failure registry-static-candidates
  fi
else
  echo '      skipped; registry candidate graph unavailable'
fi

printf '[optional 7/11] Probing preserved registry type-slot anchors\n'
if ! "$PYTHON" -m genshinre probe-registry-71 \
  "$EXE" \
  "$OUTPUT/registry-probe-71.json" \
  > /dev/null; then
  optional_failure registry-anchor-probe
fi

printf '[optional 8/11] Importing AstaPS control set\n'
control_set_ok=false
if [[ -n "$ASTAPS" ]]; then
  PACKET_OPCODES="$ASTAPS/src/main/java/emu/grasscutter/net/packet/PacketOpcodes.java"
  if [[ -f "$PACKET_OPCODES" ]]; then
    if "$PYTHON" -m genshinre import-opcodes-java "$PACKET_OPCODES" "$OUTPUT/control-set.csv"; then
      control_set_ok=true
    else
      optional_failure astaps-control-set
    fi
  else
    printf '      expected current AstaPS PacketOpcodes.java at: %s\n' "$PACKET_OPCODES" >&2
    optional_failure astaps-packet-opcodes-not-found
  fi
else
  echo '      skipped; pass --astaps DIR to generate control-set.csv'
fi

printf '[optional 9/11] Candidate graph diagnostics\n'
if [[ "$control_set_ok" == true && "$graph_ok" == true ]]; then
  if ! "$PYTHON" -m genshinre.graphdiag \
    "$OUTPUT/registry-candidate-graph.csv" \
    "$OUTPUT/control-set.csv" \
    --output "$OUTPUT/registry-candidate-graph.diagnostic.json" \
    > /dev/null; then
    optional_failure registry-candidate-diagnostics
  fi
else
  echo '      skipped; candidate graph or control set unavailable'
fi

printf '[optional 10/11] Strict candidate diagnostics\n'
if [[ "$control_set_ok" == true && "$static_candidates_ok" == true ]]; then
  if ! "$PYTHON" -m genshinre.graphdiag \
    "$OUTPUT/registry-static-candidates.csv" \
    "$OUTPUT/control-set.csv" \
    --output "$OUTPUT/registry-static-candidates.diagnostic.json" \
    > /dev/null; then
    optional_failure registry-static-diagnostics
  fi
else
  echo '      skipped; static candidates or control set unavailable'
fi

printf '[optional 11/11] Human-readable registry convergence report\n'
if [[ "$graph_ok" == true ]]; then
  REPORT_ARGS=(
    -m genshinre.registryreport
    "$OUTPUT/registry-candidate-graph.csv"
    "$OUTPUT/registry-candidate-graph.summary.json"
    "$OUTPUT/registry-candidate-report.md"
    --focus 186,9369,22899,26105
  )
  if [[ "$control_set_ok" == true ]]; then
    REPORT_ARGS+=(--known-opcodes "$OUTPUT/control-set.csv")
  fi
  if ! "$PYTHON" "${REPORT_ARGS[@]}" > "$OUTPUT/registry-candidate-report.summary.json"; then
    optional_failure registry-convergence-report
  fi
else
  echo '      skipped; registry candidate graph unavailable'
fi

printf 'Core regeneration complete: %s\n' "$OUTPUT"
if ((${#OPTIONAL_FAILURES[@]})); then
  printf 'Optional research stages with unresolved results: %s\n' "${OPTIONAL_FAILURES[*]}"
else
  printf 'All optional research stages completed.\n'
fi
