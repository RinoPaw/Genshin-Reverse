#!/usr/bin/env bash
set -euo pipefail

WORK="work/7.1.0-global/windows-x64"
VERSION="versions/7.1.0-global/windows-x64"
PYTHON="python3"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage:
  scripts/publish-artifacts-7.1.sh [--work DIR] [--version DIR] [--python PYTHON]

Publishes validated metadata and reusable intermediate artifacts. An existing
xref-published canonical registry is validated and preserved in place; this
command never replaces it through an alternate registry-recovery path.
EOF
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

"$PYTHON" -m genshinre.artifactpublish "$WORK" "$VERSION"
printf 'Published validated 7.1 research artifacts into: %s\n' "$VERSION"
printf 'Existing canonical registry identity artifacts were validated and preserved.\n'
