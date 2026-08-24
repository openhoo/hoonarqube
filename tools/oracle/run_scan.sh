#!/usr/bin/env bash
set -euo pipefail
PROJ="$1"
DIR="$(realpath .oracle/sonar/projects/$PROJ)"
TOKEN=$(cat .oracle/sonar/token)
cd "$DIR"
/tmp/sonar-scanner-6.2.1.4610-linux-x64/bin/sonar-scanner \
  -Dsonar.projectKey="$PROJ" \
  -Dsonar.login="$TOKEN" \
  -Dsonar.host.url=http://127.0.0.1:9000 \
  -Dsonar.working.directory=/tmp/sqscanner-$PROJ
