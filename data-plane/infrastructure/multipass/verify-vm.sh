#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${1:-/home/ubuntu/sdn-platform}"
DEPLOYMENT_PROFILE="${2:-dataplane}"
BACKEND_URL="${3:-http://127.0.0.1:8000}"
FRONTEND_URL="${4:-http://127.0.0.1:3000}"
CONTROLLER_HEALTH_URL="${5:-http://127.0.0.1:8080/health}"
CONTROLLER_COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"

if [[ "${DEPLOYMENT_PROFILE}" == "dataplane" ]]; then
  COMPOSE_FILE="${PROJECT_DIR}/docker-compose.dataplane.yml"
elif [[ "${DEPLOYMENT_PROFILE}" == "full" ]]; then
  COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
else
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

if [[ ! -f "${COMPOSE_FILE}" ]]; then
  echo "Compose file not found: ${COMPOSE_FILE}" >&2
  exit 1
fi

if [[ ! -f "${CONTROLLER_COMPOSE_FILE}" ]]; then
  echo "Controller Compose file not found: ${CONTROLLER_COMPOSE_FILE}" >&2
  exit 1
fi

systemctl is-active --quiet openvswitch-switch
systemctl is-active --quiet docker
docker info >/dev/null

if [[ "${DEPLOYMENT_PROFILE}" == "dataplane" ]]; then
  BACKEND_BASE_URL="${BACKEND_URL}" docker compose \
    -f "${COMPOSE_FILE}" config --quiet
else
  docker compose --profile dataplane -f "${COMPOSE_FILE}" config --quiet
fi

docker compose --profile dataplane \
  -f "${CONTROLLER_COMPOSE_FILE}" config --quiet

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
