#!/usr/bin/env bash
set -Eeuo pipefail

VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
CONTROLLER_REST_PORT="${CONTROLLER_REST_PORT:-8080}"
COMPOSE_FILE="${VM_PROJECT_DIR}/docker-compose.yml"

if ! command -v multipass >/dev/null 2>&1; then
  echo "Multipass is not installed or is not available in PATH." >&2
  exit 1
fi

if ! multipass list --format csv | \
  awk -F, -v name="${VM_NAME}" 'NR > 1 && $1 == name {found=1} END {exit !found}'; then
  echo "Multipass instance does not exist: ${VM_NAME}" >&2
  exit 1
fi

multipass start "${VM_NAME}" >/dev/null 2>&1 || true
multipass exec "${VM_NAME}" -- \
  docker compose --profile dataplane -f "${COMPOSE_FILE}" \
  up -d controller

multipass exec "${VM_NAME}" -- \
  curl --retry 15 --retry-delay 1 --retry-connrefused \
  --fail --silent --show-error --output /dev/null \
  "http://127.0.0.1:${CONTROLLER_REST_PORT}/health"

VM_IP="$(multipass list --format csv | awk -F, -v name="${VM_NAME}" '$1 == name {print $3}')"
echo "Controller is ready: http://${VM_IP}:${CONTROLLER_REST_PORT}"
