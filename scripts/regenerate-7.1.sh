#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/regenerate-7.1.sh --exe PATH --metadata PATH [--output DIR] [--python PYTHON] [--astaps DIR]
EOF
}

EXE=""
METADATA=""
OUTPUT="work/7.1.0-global/windows-x64"
PYTHON="python3"
ASTAPS=""

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

printf '[1/16] Fingerprinting exact samples\n'
"$PYTHON" -m genshinre fingerprint "$EXE" "$METADATA" > "$OUTPUT/fingerprints.json"

printf '[2/16] Decoding native 7.1 MHY metadata\n'
"$PYTHON" -m genshinre decode-metadata-71 "$EXE" "$METADATA" "$OUTPUT/metadata"

printf '[3/16] Verifying native 7.1 anchors\n'
"$PYTHON" -m genshinre verify-metadata \
  "$OUTPUT/metadata" \
  versions/7.1.0-global/windows-x64/metadata/anchors-native.json \
  > "$OUTPUT/metadata-anchor-check.json"

printf '[4/16] Exporting IL2CPP runtime type index\n'
"$PYTHON" -m genshinre.typearray \
  "$EXE" \
  "$OUTPUT/metadata/types.csv" \
  "$OUTPUT/metadata/runtime-types.csv" \
  --summary "$OUTPUT/metadata/runtime-types.summary.json" \
  > /dev/null

printf '[5/16] Scanning conservative constant-return CmdId candidates\n'
"$PYTHON" -m genshinre scan-constant-cmdids \
  "$EXE" \
  "$OUTPUT/metadata/methods.csv" \
  "$OUTPUT/getcmdid-candidates.csv" \
  --summary "$OUTPUT/getcmdid-candidates.summary.json"

printf '[6/16] Auditing metadata-usage initializer call sites\n'
"$PYTHON" -m genshinre.usage \
  "$EXE" \
  "$OUTPUT/metadata-usage-sites.csv" \
  --summary "$OUTPUT/metadata-usage-sites.summary.json" \
  --require-9369-anchor \
  > /dev/null

printf '[7/16] Probing metadata registration structure\n'
"$PYTHON" -m genshinre.metareg \
  "$EXE" \
  "$OUTPUT/metadata-registration-probe.json" \
  > /dev/null

printf '[8/16] Recovering anchored metadata usage destination table\n'
"$PYTHON" -m genshinre.metausage \
  "$EXE" \
  "$OUTPUT/metadata-usage-slots.csv" \
  --summary "$OUTPUT/metadata-usage-slots.summary.json" \
  > /dev/null

printf '[9/16] Joining metadata usages to runtime types\n'
"$PYTHON" -m genshinre.usagejoin \
  "$EXE" \
  "$OUTPUT/metadata-usage-slots.csv" \
  "$OUTPUT/metadata/runtime-types.csv" \
  "$OUTPUT/metadata-usage-types.csv" \
  --summary "$OUTPUT/metadata-usage-types.summary.json" \
  > /dev/null

printf '[10/16] Building registry candidate graph\n'
"$PYTHON" -m genshinre.registrygraph \
  "$OUTPUT/metadata-usage-types.csv" \
  "$OUTPUT/getcmdid-candidates.csv" \
  "$OUTPUT/registry-candidate-graph.csv" \
  --summary "$OUTPUT/registry-candidate-graph.summary.json" \
  --require-anchors \
  > /dev/null

printf '[11/16] Refining one-to-one static registry candidates\n'
"$PYTHON" -m genshinre.registryselect \
  "$OUTPUT/registry-candidate-graph.csv" \
  "$OUTPUT/registry-static-candidates.csv" \
  --summary "$OUTPUT/registry-static-candidates.summary.json" \
  > /dev/null

printf '[12/16] Probing preserved registry type-slot anchors\n'
"$PYTHON" -m genshinre probe-registry-71 \
  "$EXE" \
  "$OUTPUT/registry-probe-71.json" \
  > /dev/null

printf '[13/16] Optional AstaPS control set\n'
if [[ -n "$ASTAPS" ]]; then
  PACKET_OPCODES="$ASTAPS/src/main/java/emu/grasscutter/net/proto/PacketOpcodes.java"
  if [[ ! -f "$PACKET_OPCODES" ]]; then
    echo "PacketOpcodes.java not found at: $PACKET_OPCODES" >&2
    exit 1
  fi
  "$PYTHON" -m genshinre import-opcodes-java "$PACKET_OPCODES" "$OUTPUT/known-opcodes.csv"
else
  echo '      skipped; pass --astaps DIR to generate known-opcodes.csv'
fi

printf '[14/16] Candidate graph diagnostics\n'
if [[ -n "$ASTAPS" ]]; then
  "$PYTHON" -m genshinre.graphdiag \
    "$OUTPUT/registry-candidate-graph.csv" \
    "$OUTPUT/known-opcodes.csv" \
    --output "$OUTPUT/registry-candidate-graph.diagnostic.json" \
    > /dev/null
else
  echo '      skipped; AstaPS control set unavailable'
fi

printf '[15/16] Strict candidate diagnostics\n'
if [[ -n "$ASTAPS" ]]; then
  "$PYTHON" -m genshinre.graphdiag \
    "$OUTPUT/registry-static-candidates.csv" \
    "$OUTPUT/known-opcodes.csv" \
    --output "$OUTPUT/registry-static-candidates.diagnostic.json" \
    > /dev/null
else
  echo '      skipped; AstaPS control set unavailable'
fi

printf '[16/16] Human-readable registry convergence report\n'
if [[ -n "$ASTAPS" ]]; then
  "$PYTHON" -m genshinre.registryreport \
    "$OUTPUT/registry-candidate-graph.csv" \
    "$OUTPUT/registry-candidate-graph.summary.json" \
    "$OUTPUT/registry-candidate-report.md" \
    --known-opcodes "$OUTPUT/known-opcodes.csv" \
    --focus 186,9369,22899,26105 \
    > "$OUTPUT/registry-candidate-report.summary.json"
else
  "$PYTHON" -m genshinre.registryreport \
    "$OUTPUT/registry-candidate-graph.csv" \
    "$OUTPUT/registry-candidate-graph.summary.json" \
    "$OUTPUT/registry-candidate-report.md" \
    --focus 186,9369,22899,26105 \
    > "$OUTPUT/registry-candidate-report.summary.json"
fi

printf 'Done: %s\n' "$OUTPUT"
printf 'Read registry-candidate-report.md first, then compare registry-candidate-graph.diagnostic.json with registry-static-candidates.diagnostic.json. Strict candidates remain non-canonical until registration identity/direction is independently closed.\n'
