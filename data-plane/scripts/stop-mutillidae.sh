#!/usr/bin/env bash
set -Eeuo pipefail

VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
COMPOSE_DIR="${VM_PROJECT_DIR}/data-plane/web/mutillidae"

if ! multipass list --format csv | \
  awk -F, -v name="${VM_NAME}" 'NR > 1 && $1 == name {found=1} END {exit !found}'; then
  echo "Multipass instance does not exist: ${VM_NAME}" >&2
  exit 1
fi

DOCKER_ARCH="$(
  multipass exec "${VM_NAME}" -- \
    docker info --format '{{.Architecture}}'
)"

case "${DOCKER_ARCH}" in
  amd64|x86_64)
    COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"
    ;;
  arm64|aarch64)
    COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.arm64.yml"
    ;;
  *)
    echo "Unsupported Docker architecture: ${DOCKER_ARCH}" >&2
    exit 1
    ;;
esac

multipass exec "${VM_NAME}" -- \
  sudo systemctl stop sdn-mutillidae-relay >/dev/null 2>&1 || true

multipass exec "${VM_NAME}" -- \
  docker compose --project-name sdn-mutillidae --file "${COMPOSE_FILE}" \
  down --timeout 5

echo "Mutillidae containers stopped. Persistent volumes were preserved."
