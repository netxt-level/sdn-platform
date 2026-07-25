#!/usr/bin/env bash
set -Eeuo pipefail

VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
MUTILLIDAE_HOST_PORT="${MUTILLIDAE_HOST_PORT:-8088}"
COMPOSE_DIR="${VM_PROJECT_DIR}/data-plane/web/mutillidae"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.yml"
INITIALIZE=false
PULL=false

usage() {
  cat <<'EOF'
Usage: start-mutillidae.sh [--initialize] [--pull]

Starts the intentionally vulnerable Mutillidae containers inside sdn-lab.
The web service is published only on the VM loopback interface.

  --initialize  Build/reset the Mutillidae database after startup.
  --pull        Pull the official prebuilt images before startup.
EOF
}

while (($#)); do
  case "$1" in
    --initialize)
      INITIALIZE=true
      ;;
    --pull)
      PULL=true
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

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

if ! multipass exec "${VM_NAME}" -- test -f "${COMPOSE_FILE}"; then
  echo "Mutillidae Compose file does not exist in the VM: ${COMPOSE_FILE}" >&2
  echo "Run ./data-plane/scripts/sync-vm.sh first." >&2
  exit 1
fi

DOCKER_ARCH="$(
  multipass exec "${VM_NAME}" -- \
    docker info --format '{{.Architecture}}'
)"
BUILD_ARGS=()
PULL_ARGS=()

case "${DOCKER_ARCH}" in
  amd64|x86_64)
    ;;
  arm64|aarch64)
    COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.arm64.yml"
    BUILD_ARGS+=(--build)
    PULL_ARGS+=(--ignore-buildable)
    ;;
  *)
    echo "Unsupported Docker architecture: ${DOCKER_ARCH}" >&2
    exit 1
    ;;
esac

COMPOSE=(
  docker compose
  --project-name sdn-mutillidae
  --file "${COMPOSE_FILE}"
)

if [[ "${PULL}" == true ]]; then
  multipass exec "${VM_NAME}" -- env \
    MUTILLIDAE_HOST_PORT="${MUTILLIDAE_HOST_PORT}" \
    "${COMPOSE[@]}" pull "${PULL_ARGS[@]}"
fi

multipass exec "${VM_NAME}" -- env \
  MUTILLIDAE_HOST_PORT="${MUTILLIDAE_HOST_PORT}" \
  "${COMPOSE[@]}" up --detach "${BUILD_ARGS[@]}"

multipass exec "${VM_NAME}" -- \
  curl --retry 30 --retry-delay 1 --retry-connrefused \
  --fail --silent --show-error --output /dev/null \
  --header 'Host: mutillidae.localhost' \
  "http://127.0.0.1:${MUTILLIDAE_HOST_PORT}/"

if [[ "${INITIALIZE}" == true ]]; then
  multipass exec "${VM_NAME}" -- \
    curl --fail --silent --show-error --output /dev/null \
    --header 'Host: mutillidae.localhost' \
    "http://127.0.0.1:${MUTILLIDAE_HOST_PORT}/set-up-database.php"
fi

echo "Mutillidae is ready on VM loopback port ${MUTILLIDAE_HOST_PORT} (${DOCKER_ARCH})."
echo "Start Mininet with --mutillidae-proxy to expose it only as web (10.0.0.100)."
