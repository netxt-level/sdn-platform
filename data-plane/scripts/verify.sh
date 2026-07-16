#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
CONTROLLER_OPENFLOW_PORT="${CONTROLLER_OPENFLOW_PORT:-6653}"
CONTROLLER_REST_PORT="${CONTROLLER_REST_PORT:-8080}"
CONTROLLER_CONTAINER="${CONTROLLER_CONTAINER:-sdn-controller}"
SCENARIO="${VM_PROJECT_DIR}/data-plane/mininet/scenarios/failover.py"

"${SCRIPT_DIR}/start.sh"

multipass exec "${VM_NAME}" -- sudo python3 -u "${SCENARIO}" \
  --controller-host 127.0.0.1 \
  --controller-port "${CONTROLLER_OPENFLOW_PORT}" \
  --controller-rest-port "${CONTROLLER_REST_PORT}" \
  --controller-container "${CONTROLLER_CONTAINER}"

if [[ -n "$(multipass exec "${VM_NAME}" -- sudo ovs-vsctl list-br)" ]]; then
  echo "Stale OVS bridges remain after validation." >&2
  exit 1
fi

echo "Data-plane failover validation passed."
