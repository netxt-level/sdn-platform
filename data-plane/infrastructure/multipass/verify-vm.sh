#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${1:-/home/ubuntu/sdn-platform}"
DEPLOYMENT_PROFILE="${2:-dataplane}"
BACKEND_URL="${3:-http://127.0.0.1:8000}"
FRONTEND_URL="${4:-http://127.0.0.1:3000}"
CONTROLLER_HEALTH_URL="${5:-http://127.0.0.1:8080/health}"
ANALYZER_INTERFACE="${6:-sdn-sensor0}"
BASE_COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
DATAPLANE_COMPOSE_FILE="${PROJECT_DIR}/docker-compose.dataplane.yml"

if [[ "${DEPLOYMENT_PROFILE}" != "dataplane" && "${DEPLOYMENT_PROFILE}" != "full" ]]; then
  echo "Unsupported deployment profile: ${DEPLOYMENT_PROFILE}" >&2
  exit 2
fi

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command is missing: $1" >&2
    exit 1
  fi
}

require_command mn
require_command ovs-vsctl
require_command docker
require_command curl

if [[ ! -f "${BASE_COMPOSE_FILE}" ]]; then
  echo "Compose file not found: ${BASE_COMPOSE_FILE}" >&2
  exit 1
fi

if [[ ! -f "${DATAPLANE_COMPOSE_FILE}" ]]; then
  echo "Compose file not found: ${DATAPLANE_COMPOSE_FILE}" >&2
  exit 1
fi

systemctl is-active --quiet openvswitch-switch
systemctl is-active --quiet docker
docker info >/dev/null

BACKEND_BASE_URL="${BACKEND_URL}" ANALYZER_INTERFACE="${ANALYZER_INTERFACE}" \
  docker compose --profile dataplane \
  -f "${BASE_COMPOSE_FILE}" \
  -f "${DATAPLANE_COMPOSE_FILE}" \
  config --quiet

if ! ip link show dev "${ANALYZER_INTERFACE}" >/dev/null 2>&1; then
  echo "Analyzer interface is missing: ${ANALYZER_INTERFACE}" >&2
  exit 1
fi

cleanup_mininet() {
  sudo mn -c >/dev/null 2>&1 || true
}

trap cleanup_mininet EXIT
cleanup_mininet
sudo mn \
  --test pingall \
  --topo single,2 \
  --switch ovsbr \
  --controller none

curl \
  --retry 30 \
  --retry-delay 2 \
  --retry-connrefused \
  --fail \
  --silent \
  --show-error \
  "${BACKEND_URL}/health" >/dev/null

curl \
  --retry 30 \
  --retry-delay 2 \
  --retry-connrefused \
  --fail \
  --silent \
  --show-error \
  --head \
  "${FRONTEND_URL}" >/dev/null

curl \
  --retry 30 \
  --retry-delay 2 \
  --retry-connrefused \
  --fail \
  --silent \
  --show-error \
  "${CONTROLLER_HEALTH_URL}" >/dev/null

if [[ "${DEPLOYMENT_PROFILE}" == "dataplane" ]]; then
  REQUIRED_CONTAINERS=(sdn-controller sdn-analyzer)
  FORBIDDEN_CONTAINERS=(
    sdn-postgres
    sdn-influxdb
    sdn-elasticsearch
    sdn-backend
    sdn-frontend
  )
else
  REQUIRED_CONTAINERS=(
    sdn-postgres
    sdn-influxdb
    sdn-elasticsearch
    sdn-backend
    sdn-analyzer
    sdn-frontend
    sdn-controller
  )
  FORBIDDEN_CONTAINERS=()
fi

for container in "${REQUIRED_CONTAINERS[@]}"; do
  if [[ "$(docker inspect --format '{{.State.Running}}' "${container}")" != "true" ]]; then
    echo "Container is not running: ${container}" >&2
    exit 1
  fi
done

if [[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' sdn-analyzer)" != "host" ]]; then
  echo "Analyzer must run with host networking." >&2
  exit 1
fi

if ! docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' sdn-analyzer |
  grep -Fxq "ANALYZER_INTERFACE=${ANALYZER_INTERFACE}"; then
  echo "Analyzer is not configured for ${ANALYZER_INTERFACE}." >&2
  exit 1
fi

if ! docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' sdn-analyzer |
  awk -F= '$1 == "ANALYZER_API_KEY" && length(substr($0, index($0, "=") + 1)) > 0 { found = 1 } END { exit !found }'; then
  echo "Analyzer API key is missing; secure-default delivery cannot succeed." >&2
  exit 1
fi

if [[ -z "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/sdn-analyzer"}}{{println .Name}}{{end}}{{end}}' sdn-analyzer)" ]]; then
  echo "Analyzer Outbox volume is not mounted at /var/lib/sdn-analyzer." >&2
  exit 1
fi

if [[ "${DEPLOYMENT_PROFILE}" == "dataplane" ]]; then
  sleep 3
  for container in sdn-controller sdn-analyzer; do
    if [[ "$(docker inspect --format '{{.State.Running}}' "${container}")" != "true" ]]; then
      echo "Container stopped after startup: ${container}" >&2
      docker logs --tail 20 "${container}" >&2
      exit 1
    fi
    if [[ "$(docker inspect --format '{{.RestartCount}}' "${container}")" != "0" ]]; then
      echo "Container entered a restart loop: ${container}" >&2
      docker logs --tail 20 "${container}" >&2
      exit 1
    fi
  done
fi

for container in "${FORBIDDEN_CONTAINERS[@]}"; do
  if docker inspect "${container}" >/dev/null 2>&1 && \
    [[ "$(docker inspect --format '{{.State.Running}}' "${container}")" == "true" ]]; then
    echo "Control-plane container must not run in the data-plane VM: ${container}" >&2
    exit 1
  fi
done

echo "Environment verification passed for profile: ${DEPLOYMENT_PROFILE}."
