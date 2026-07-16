#!/usr/bin/env bash
set -Eeuo pipefail

VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
COMPOSE_FILE="${VM_PROJECT_DIR}/docker-compose.yml"

if ! multipass list --format csv | \
  awk -F, -v name="${VM_NAME}" 'NR > 1 && $1 == name {found=1} END {exit !found}'; then
  echo "Multipass instance does not exist: ${VM_NAME}" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- \
  docker compose --profile dataplane -f "${COMPOSE_FILE}" \
  stop --timeout 5 controller
multipass exec "${VM_NAME}" -- \
  docker compose --profile dataplane -f "${COMPOSE_FILE}" \
  rm -f controller
multipass exec "${VM_NAME}" -- sudo mn -c

echo "Controller container and stale Mininet/OVS state were removed."
