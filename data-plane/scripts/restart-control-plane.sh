#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VM_NAME="${VM_NAME:-sdn-lab}"
BACKEND_CONTAINER="${BACKEND_CONTAINER:-sdn-backend}"
FRONTEND_CONTAINER="${FRONTEND_CONTAINER:-sdn-frontend}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-sdn-platform-v1}"
ENV_FILE="${REPO_ROOT}/.env"

SERVICES=("$@")
if [[ ${#SERVICES[@]} -eq 0 ]]; then
  SERVICES=(backend frontend)
fi

read_container_env() {
  local name="$1"

  if ! docker inspect "${BACKEND_CONTAINER}" >/dev/null 2>&1; then
    return 0
  fi

  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
    "${BACKEND_CONTAINER}" 2>/dev/null | sed -n "s/^${name}=//p"
}

read_env_file() {
  local name="$1"
  local value

  if [[ ! -f "${ENV_FILE}" ]]; then
    return 0
  fi

  value="$(awk -F= -v key="${name}" '
    $1 == key {
      sub(/^[^=]*=/, "")
      print
      exit
    }
  ' "${ENV_FILE}")"
  value="${value#\"}"
  value="${value%\"}"
  value="${value#\'}"
  value="${value%\'}"
  printf '%s' "${value}"
}

resolve_required_secret() {
  local name="$1"
  local value="${!name:-}"

  if [[ -z "${value}" ]]; then
    value="$(read_container_env "${name}")"
  fi
  if [[ -z "${value}" ]]; then
    value="$(read_env_file "${name}")"
  fi
  if [[ -z "${value}" ]]; then
    echo "Missing required ${name}. Set it in .env or keep ${BACKEND_CONTAINER} available for value recovery." >&2
    exit 2
  fi

  printf '%s' "${value}"
}

ADMIN_API_KEY="$(resolve_required_secret ADMIN_API_KEY)"
ANALYZER_API_KEY="$(resolve_required_secret ANALYZER_API_KEY)"
CONTROLLER_API_KEY="$(resolve_required_secret CONTROLLER_API_KEY)"
WEBSOCKET_TOKEN_SECRET="$(resolve_required_secret WEBSOCKET_TOKEN_SECRET)"

if ! command -v multipass >/dev/null 2>&1; then
  echo "Multipass is required to resolve the Controller and host gateway addresses." >&2
  exit 2
fi

multipass start "${VM_NAME}" >/dev/null 2>&1 || true
VM_IP="$(multipass list --format csv | awk -F, -v name="${VM_NAME}" '$1 == name {print $3; exit}')"
BACKEND_VM_BIND_ADDRESS="${BACKEND_VM_BIND_ADDRESS:-$(
  multipass exec "${VM_NAME}" -- ip route show default | awk '{print $3; exit}'
)}"
CONTROLLER_BASE_URL="${CONTROLLER_BASE_URL:-http://${VM_IP}:8080}"

if [[ -z "${VM_IP}" || -z "${BACKEND_VM_BIND_ADDRESS}" ]]; then
  echo "Could not resolve Multipass networking for ${VM_NAME}." >&2
  exit 2
fi

curl --max-time 5 --fail --silent --show-error --output /dev/null \
  "${CONTROLLER_BASE_URL}/health"

export ADMIN_API_KEY
export ANALYZER_API_KEY
export CONTROLLER_API_KEY
export WEBSOCKET_TOKEN_SECRET
export BACKEND_VM_BIND_ADDRESS
export CONTROLLER_BASE_URL

COMPOSE=(
  docker compose
  -p "${COMPOSE_PROJECT_NAME}"
  -f "${REPO_ROOT}/docker-compose.yml"
  -f "${REPO_ROOT}/docker-compose.control-plane.yml"
)

"${COMPOSE[@]}" up -d --build --no-deps "${SERVICES[@]}"

has_service() {
  local expected="$1"
  local service

  for service in "${SERVICES[@]}"; do
    if [[ "${service}" == "${expected}" ]]; then
      return 0
    fi
  done
  return 1
}

wait_for_http() {
  local label="$1"
  shift

  if ! curl --retry 30 --retry-delay 1 --retry-connrefused --retry-all-errors \
    --max-time 15 --fail --silent --output /dev/null "$@"; then
    echo "${label} readiness check failed." >&2
    return 1
  fi
}

if has_service backend; then
  wait_for_http "Backend health" http://127.0.0.1:8000/health
  wait_for_http "Backend Controller API" \
    -H "X-API-Key: ${ADMIN_API_KEY}" \
    http://127.0.0.1:8000/api/path/status
fi

if has_service frontend; then
  wait_for_http "Frontend API proxy" http://127.0.0.1:3000/api/path/status
  wait_for_http "WebSocket token API" \
    -X POST http://127.0.0.1:3000/ws/token
fi

echo "Control plane ready: frontend=http://127.0.0.1:3000 backend=http://127.0.0.1:8000 controller=${CONTROLLER_BASE_URL}"
