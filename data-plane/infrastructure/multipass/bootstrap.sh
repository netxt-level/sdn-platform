#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
CLOUD_INIT="${SCRIPT_DIR}/cloud-init.yaml"

VM_NAME="${VM_NAME:-sdn-lab}"
VM_CPUS="${VM_CPUS:-4}"
VM_MEMORY="${VM_MEMORY:-8G}"
VM_DISK="${VM_DISK:-40G}"
VM_IMAGE="${VM_IMAGE:-24.04}"
DEPLOYMENT_PROFILE="${DEPLOYMENT_PROFILE:-dataplane}"
VM_ANALYZER_INTERFACE="${VM_ANALYZER_INTERFACE:-auto}"
VM_PROJECT_DIR="/home/ubuntu/sdn-platform"

usage() {
  cat <<'EOF'
Usage: bootstrap.sh [options]

Options:
  --name NAME       Multipass instance name (default: sdn-lab)
  --cpus COUNT      CPU count (default: 4)
  --memory SIZE     Memory size (default: 8G)
  --disk SIZE       Disk size (default: 40G)
  --image IMAGE     Ubuntu image (default: 24.04)
  --profile PROFILE Deployment profile: dataplane or full (default: dataplane)
  --interface NAME  Analyzer capture interface in the VM (default: auto)
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      VM_NAME="$2"
      shift 2
      ;;
    --cpus)
      VM_CPUS="$2"
      shift 2
      ;;
    --memory)
      VM_MEMORY="$2"
      shift 2
      ;;
    --disk)
      VM_DISK="$2"
      shift 2
      ;;
    --image)
      VM_IMAGE="$2"
      shift 2
      ;;
    --profile)
      DEPLOYMENT_PROFILE="$2"
      shift 2
      ;;
    --interface)
      VM_ANALYZER_INTERFACE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${DEPLOYMENT_PROFILE}" != "dataplane" && "${DEPLOYMENT_PROFILE}" != "full" ]]; then
  echo "Unsupported deployment profile: ${DEPLOYMENT_PROFILE}" >&2
  exit 2
fi

REQUIRED_COMMANDS=(multipass tar)
if [[ "${DEPLOYMENT_PROFILE}" == "dataplane" ]]; then
  REQUIRED_COMMANDS+=(docker curl)
fi

for command_name in "${REQUIRED_COMMANDS[@]}"; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Required command is missing: ${command_name}" >&2
    exit 1
  fi
done

if [[ ! -f "${REPO_ROOT}/.env" ]]; then
  echo "Missing ${REPO_ROOT}/.env" >&2
  exit 1
fi

if [[ ! -f "${CLOUD_INIT}" ]]; then
  echo "Missing cloud-init file: ${CLOUD_INIT}" >&2
  exit 1
fi

if multipass info "${VM_NAME}" >/dev/null 2>&1; then
  echo "Reusing Multipass instance: ${VM_NAME}"
  multipass start "${VM_NAME}" >/dev/null 2>&1 || true
else
  echo "Creating ${VM_NAME}: Ubuntu ${VM_IMAGE}, ${VM_CPUS} CPU, ${VM_MEMORY} RAM, ${VM_DISK} disk"
  multipass launch "${VM_IMAGE}" \
    --name "${VM_NAME}" \
    --cpus "${VM_CPUS}" \
    --memory "${VM_MEMORY}" \
    --disk "${VM_DISK}" \
    --cloud-init "${CLOUD_INIT}"
fi

echo "Waiting for cloud-init to finish..."
multipass exec "${VM_NAME}" -- sudo cloud-init status --wait

echo "Ensuring Ubuntu packages are installed..."
multipass transfer \
  "${SCRIPT_DIR}/provision.sh" \
  "${VM_NAME}:/home/ubuntu/provision-ubuntu.sh"
multipass exec "${VM_NAME}" -- \
  sudo bash /home/ubuntu/provision-ubuntu.sh
multipass exec "${VM_NAME}" -- \
  rm -f /home/ubuntu/provision-ubuntu.sh

ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/sdn-platform.XXXXXX.tar.gz")"
REMOTE_ARCHIVE="/home/ubuntu/sdn-platform-source.tar.gz"

cleanup() {
  rm -f "${ARCHIVE}"
  multipass exec "${VM_NAME}" -- rm -f "${REMOTE_ARCHIVE}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Packing the project without generated files..."
TAR_OPTIONS=(
  -czf "${ARCHIVE}"
  --format=ustar
  --exclude=.git
  --exclude=.venv
  --exclude=.pytest_cache
  --exclude=frontend/node_modules
  --exclude=frontend/.next
  --exclude=frontend/tsconfig.tsbuildinfo
  --exclude='*/__pycache__'
  --exclude='*.pyc'
)

COPYFILE_DISABLE=1 tar "${TAR_OPTIONS[@]}" -C "${REPO_ROOT}" .

echo "Synchronizing the project into ${VM_NAME}:${VM_PROJECT_DIR}..."
multipass transfer "${ARCHIVE}" "${VM_NAME}:${REMOTE_ARCHIVE}"
multipass exec "${VM_NAME}" -- rm -rf /home/ubuntu/sdn-platform-next
multipass exec "${VM_NAME}" -- mkdir -p /home/ubuntu/sdn-platform-next
multipass exec "${VM_NAME}" -- \
  tar -xzf "${REMOTE_ARCHIVE}" -C /home/ubuntu/sdn-platform-next
multipass exec "${VM_NAME}" -- rm -rf "${VM_PROJECT_DIR}"
multipass exec "${VM_NAME}" -- \
  mv /home/ubuntu/sdn-platform-next "${VM_PROJECT_DIR}"
multipass exec "${VM_NAME}" -- rm -f "${REMOTE_ARCHIVE}"

VM_IP="$(multipass info "${VM_NAME}" | awk '/IPv4:/ {print $2; exit}')"

if [[ "${DEPLOYMENT_PROFILE}" == "dataplane" ]]; then
  HOST_GATEWAY="$(multipass exec "${VM_NAME}" -- ip route show default | awk '{print $3; exit}')"
  RESOLVED_ANALYZER_INTERFACE="${VM_ANALYZER_INTERFACE}"
  if [[ "${RESOLVED_ANALYZER_INTERFACE}" == "auto" ]]; then
    RESOLVED_ANALYZER_INTERFACE="$(
      multipass exec "${VM_NAME}" -- ip route show default |
        awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}'
    )"
  fi
  if [[ -z "${RESOLVED_ANALYZER_INTERFACE}" ]]; then
    echo "Could not determine the Analyzer interface in the VM." >&2
    exit 1
  fi
  BACKEND_URL="http://${HOST_GATEWAY}:8000"
  FRONTEND_URL="http://${HOST_GATEWAY}:${FRONTEND_PORT:-3000}"
  CONTROL_COMPOSE=(
    docker compose
    -f "${REPO_ROOT}/docker-compose.yml"
    -f "${REPO_ROOT}/docker-compose.control-plane.yml"
  )

  echo "Starting backend, frontend, and databases on the host..."
  "${CONTROL_COMPOSE[@]}" config --quiet
  "${CONTROL_COMPOSE[@]}" stop analyzer >/dev/null 2>&1 || true
  "${CONTROL_COMPOSE[@]}" rm -f analyzer >/dev/null 2>&1 || true
  "${CONTROL_COMPOSE[@]}" up -d --build \
    postgres influxdb elasticsearch backend frontend

  echo "Waiting for the host PostgreSQL service..."
  POSTGRES_READY=false
  for _ in $(seq 1 30); do
    if "${CONTROL_COMPOSE[@]}" exec -T postgres \
      sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then
      POSTGRES_READY=true
      break
    fi
    sleep 2
  done
  if [[ "${POSTGRES_READY}" != "true" ]]; then
    echo "Host PostgreSQL did not become ready." >&2
    exit 1
  fi

  echo "Applying database migrations on the host..."
  "${CONTROL_COMPOSE[@]}" run --rm migrate

  echo "Stopping the previous full stack in the VM, if present..."
  multipass exec "${VM_NAME}" -- \
    docker compose -f "${VM_PROJECT_DIR}/docker-compose.yml" down --remove-orphans

  echo "Starting the Analyzer in the VM..."
  multipass exec "${VM_NAME}" -- \
    env BACKEND_BASE_URL="${BACKEND_URL}" ANALYZER_INTERFACE="${RESOLVED_ANALYZER_INTERFACE}" \
    docker compose -f "${VM_PROJECT_DIR}/docker-compose.dataplane.yml" \
    up -d --build

  echo "Verifying the hybrid data-plane environment..."
  multipass exec "${VM_NAME}" -- \
    bash "${VM_PROJECT_DIR}/data-plane/infrastructure/multipass/verify-vm.sh" \
    "${VM_PROJECT_DIR}" dataplane "${BACKEND_URL}" "${FRONTEND_URL}"

  curl --retry 10 --retry-delay 2 --retry-connrefused \
    --fail --silent --show-error http://127.0.0.1:8000/health >/dev/null
  curl --retry 10 --retry-delay 2 --retry-connrefused \
    --fail --silent --show-error --head \
    "http://127.0.0.1:${FRONTEND_PORT:-3000}" >/dev/null

  echo
  echo "Hybrid SDN lab is ready."
  echo "Profile:   dataplane"
  echo "VM:        ${VM_NAME} (${VM_IP})"
  echo "Analyzer:  VM host network (${RESOLVED_ANALYZER_INTERFACE})"
  echo "Frontend:  http://127.0.0.1:${FRONTEND_PORT:-3000}"
  echo "Backend:   http://127.0.0.1:8000"
  echo "API docs:  http://127.0.0.1:8000/docs"
else
  echo "Building and starting the full platform in the VM..."
  multipass exec "${VM_NAME}" -- \
    docker compose -f "${VM_PROJECT_DIR}/docker-compose.yml" config --quiet
  multipass exec "${VM_NAME}" -- \
    docker compose -f "${VM_PROJECT_DIR}/docker-compose.yml" up -d --build

  echo "Applying database migrations in the VM..."
  multipass exec "${VM_NAME}" -- \
    docker compose -f "${VM_PROJECT_DIR}/docker-compose.yml" run --rm \
    -v "${VM_PROJECT_DIR}/alembic.ini:/app/alembic.ini:ro" \
    -v "${VM_PROJECT_DIR}/migrations:/app/migrations:ro" \
    backend alembic upgrade head

  echo "Verifying Mininet, OVS, Docker, and service health..."
  multipass exec "${VM_NAME}" -- \
    bash "${VM_PROJECT_DIR}/data-plane/infrastructure/multipass/verify-vm.sh" \
    "${VM_PROJECT_DIR}" full

  echo
  echo "Full VM SDN lab is ready."
  echo "Profile:  full"
  echo "VM:       ${VM_NAME} (${VM_IP})"
  echo "Frontend: http://${VM_IP}:3000"
  echo "Backend:  http://${VM_IP}:8000"
  echo "API docs: http://${VM_IP}:8000/docs"
fi
