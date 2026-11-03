#!/usr/bin/env bash
# Egress restriction for Docker-mode scan workers.
#
#   workers --> [vulnsight-scan: internal network, no route out] --> vulnsight-proxy --> internet
#
# The worker network is created with --internal, so containers on it cannot reach anything except
# each other. The allowlist proxy is attached to that network AND to a normal bridge network, and is
# the only thing with a route out. Run once per Docker host, then set on the API/worker process:
#   VULNSIGHT_EGRESS_PROXY=http://vulnsight-proxy:3128
#
# Not yet run on a real Docker host: see docs/STATUS.md.
set -euo pipefail

IMAGE="${VULNSIGHT_WORKER_IMAGE:-vulnsight-worker:latest}"

docker network inspect vulnsight-scan >/dev/null 2>&1 || docker network create --internal vulnsight-scan
docker network inspect vulnsight-out  >/dev/null 2>&1 || docker network create vulnsight-out

docker rm -f vulnsight-proxy >/dev/null 2>&1 || true
docker run -d --name vulnsight-proxy --restart unless-stopped \
  --network vulnsight-out \
  --user 10001:10001 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m --pids-limit 256 \
  --env "VULNSIGHT_EGRESS_ALLOW=${VULNSIGHT_EGRESS_ALLOW:-}" \
  --entrypoint node "$IMAGE" /app/src/platform/egress-proxy.js
docker network connect vulnsight-scan vulnsight-proxy

echo "Proxy ready. Set VULNSIGHT_EGRESS_PROXY=http://vulnsight-proxy:3128"
echo "Check:  docker run --rm --network vulnsight-scan alpine wget -T3 -qO- https://example.com   (must FAIL)"
