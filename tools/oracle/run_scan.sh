#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: $0 oracle-{py,js,ts,cs,go,rust}" >&2
  exit 2
fi
PROJ="$1"
case "$PROJ" in
  oracle-py|oracle-js|oracle-ts|oracle-cs|oracle-go|oracle-rust) ;;
  *) echo "invalid oracle project: $PROJ" >&2; exit 2 ;;
esac
REPO="$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")"
DIR="$REPO/.oracle/sonar/projects/$PROJ"
if [[ ! -d "$DIR" ]]; then
  echo "oracle project does not exist: $DIR" >&2
  exit 1
fi
TOKEN="${SONAR_ORACLE_TOKEN:-}"
TOKEN_FILE="$REPO/.oracle/sonar/token"
if [[ -z "$TOKEN" && -e "$TOKEN_FILE" ]]; then
  if [[ ! -f "$TOKEN_FILE" || -L "$TOKEN_FILE" || ! -O "$TOKEN_FILE" ]]; then
    echo "oracle token must be a caller-owned regular non-symlink file" >&2
    exit 1
  fi
  TOKEN_MODE="$(stat -c '%a' -- "$TOKEN_FILE")"
  if (( (8#$TOKEN_MODE & 077) != 0 )); then
    echo "oracle token permissions must not grant group/other access" >&2
    exit 1
  fi
  TOKEN="$(<"$TOKEN_FILE")"
fi
if [[ -z "$TOKEN" ]]; then
  echo "set SONAR_ORACLE_TOKEN or create .oracle/sonar/token" >&2
  exit 1
fi
SCANNER="${SONAR_SCANNER:-sonar-scanner}"
if ! SCANNER_PATH="$(command -v "$SCANNER")"; then
  echo "Sonar scanner not found: $SCANNER" >&2
  exit 1
fi
WORKING="$(mktemp -d -t "sqscanner-$PROJ-XXXXXXXX")"
trap 'rm -rf -- "$WORKING"' EXIT
export SONAR_TOKEN="$TOKEN"
cd "$DIR"
timeout --foreground 1800 "$SCANNER_PATH" \
  -Dsonar.projectKey="$PROJ" \
  -Dsonar.host.url=http://127.0.0.1:9000 \
  -Dsonar.working.directory="$WORKING"
