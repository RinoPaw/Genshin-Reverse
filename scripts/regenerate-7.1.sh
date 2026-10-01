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

printf '[1/5] Fingerprinting exact samples\n'
"$PYTHON" -m genshinre fingerprint "$EXE" "$METADATA" > "$OUTPUT/fingerprints.json"

printf '[2/5] Decoding native 7.1 MHY metadata\n'
"$PYTHON" -m genshinre decode-metadata-71 "$EXE" "$METADATA" "$OUTPUT/metadata"

printf '[3/5] Verifying native 7.1 anchors\n'
"$PYTHON" -m genshinre verify-metadata \
  "$OUTPUT/metadata" \
  versions/7.1.0-global/windows-x64/metadata/anchors-native.json \
  > "$OUTPUT/metadata-anchor-check.json"

printf '[4/5] Scanning conservative constant-return CmdId candidates\n'
"$PYTHON" -m genshinre scan-constant-cmdids \
  "$EXE" \
  "$OUTPUT/metadata/methods.csv" \
  "$OUTPUT/getcmdid-candidates.csv" \
  --summary "$OUTPUT/getcmdid-candidates.summary.json"

printf '[5/5] Optional AstaPS control set\n'
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

printf 'Done: %s\n' "$OUTPUT"
printf 'Next: inspect getcmdid-candidates.summary.json and continue Stage 2 registration-table recovery.\n'
