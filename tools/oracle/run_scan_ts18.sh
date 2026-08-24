#!/usr/bin/env bash
set -euo pipefail
REPO="$(git rev-parse --show-toplevel)"
PROJ="oracle-ts"
DIR="$REPO/.oracle/sonar/projects/$PROJ"
TOKEN=$(cat "$REPO/.oracle/sonar/token")
mkdir -p /tmp/node18dir
ln -sf /tmp/node18 /tmp/node18dir/node
cd "$DIR"
PATH="/tmp/node18dir:$PATH" /tmp/sonar-scanner-6.2.1.4610-linux-x64/bin/sonar-scanner \
  -Dsonar.projectKey=$PROJ \
  -Dsonar.login="$TOKEN" \
  -Dsonar.host.url=http://127.0.0.1:9000 \
  -Dsonar.nodejs.executable=/tmp/node18 \
  -Dsonar.working.directory=/tmp/sqscanner-$PROJ
