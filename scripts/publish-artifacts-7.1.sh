#!/usr/bin/env bash
set -euo pipefail

WORK="work/7.1.0-global/windows-x64"
VERSION="versions/7.1.0-global/windows-x64"
CANONICAL=""
PYTHON="python3"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --canonical-registry) CANONICAL="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage:
  scripts/publish-artifacts-7.1.sh [--work DIR] [--version DIR] [--canonical-registry DIR] [--python PYTHON]
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ARGS=(-m genshinre.artifactpublish "$WORK" "$VERSION")
if [[ -n "$CANONICAL" ]]; then
  ARGS+=(--canonical-registry "$CANONICAL")
fi

"$PYTHON" "${ARGS[@]}"
printf 'Published validated 7.1 research artifacts into: %s\n' "$VERSION"
printf 'Canonical registry files are emitted only when the stricter registry publication gate has already passed.\n'
