#!/usr/bin/env bash
set -euo pipefail

image="${1:-servercompass-client-portal-broker:smoke}"
container="servercompass-portal-broker-smoke-${RANDOM}"

cleanup() {
  docker rm --force "${container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach \
  --name "${container}" \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env PORTAL_ADMIN_TOKEN=admin-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --env PORTAL_GATEWAY_TOKEN=gateway-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --env PORTAL_SESSION_SECRET=session-secret-cccccccccccccccccccccccccccccccc \
  --env PORTAL_DB_PATH=/tmp/portal.db \
  "${image}" >/dev/null

for _ in $(seq 1 30); do
  if docker exec "${container}" node --input-type=module -e "
    const response = await fetch('http://127.0.0.1:4101/admin/health', {
      headers: { authorization: 'Bearer ' + process.env.PORTAL_ADMIN_TOKEN },
    });
    if (!response.ok) process.exit(1);
    const health = await response.json();
    if (!health.healthy || health.protocolVersion !== 3) process.exit(1);
  " >/dev/null 2>&1; then
    exit 0
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' "${container}")" != "true" ]; then
    break
  fi
  sleep 1
done

docker logs "${container}" >&2
exit 1
