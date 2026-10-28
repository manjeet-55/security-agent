#!/bin/sh
# Runs the secagent collector inside both lab containers and stores the snapshots in lab/project.
# Needs the lab running (docker compose -f lab/docker-compose.yml up -d) and network access from the containers (apt-get update).
set -eu
cd "$(dirname "$0")/.."
for pair in bad-site:bad-host good-site:good-host; do
  service=${pair%%:*}
  host=${pair#*:}
  docker compose -f lab/docker-compose.yml exec -T "$service" sh -c 'apt-get update -qq >/dev/null 2>&1 || true'
  docker compose -f lab/docker-compose.yml exec -T "$service" sh -s < assets/collector.sh > "lab/.snapshot-$host.json"
  npm run --silent dev -- snapshot add --dir lab/project --host "$host" "lab/.snapshot-$host.json"
  rm -f "lab/.snapshot-$host.json"
done
