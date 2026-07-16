#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
CONTROLLER_OPENFLOW_PORT="${CONTROLLER_OPENFLOW_PORT:-6653}"
CONTROLLER_REST_PORT="${CONTROLLER_REST_PORT:-8080}"
CONTROLLER_CONTAINER="${CONTROLLER_CONTAINER:-sdn-controller}"
FAILOVER_SCENARIO="${VM_PROJECT_DIR}/data-plane/mininet/scenarios/failover.py"
HOST_SPOOFING_SCENARIO="${VM_PROJECT_DIR}/data-plane/mininet/scenarios/host_spoofing.py"
PERFORMANCE_SCENARIO="${VM_PROJECT_DIR}/data-plane/mininet/scenarios/link_performance.py"

"${SCRIPT_DIR}/sync-vm.sh"
CONTROLLER_REBUILD=true "${SCRIPT_DIR}/start.sh"

multipass exec "${VM_NAME}" -- sudo python3 -u "${FAILOVER_SCENARIO}" \
  --controller-host 127.0.0.1 \
  --controller-port "${CONTROLLER_OPENFLOW_PORT}" \
  --controller-rest-port "${CONTROLLER_REST_PORT}" \
  --controller-container "${CONTROLLER_CONTAINER}"

multipass exec "${VM_NAME}" -- sudo python3 -u "${HOST_SPOOFING_SCENARIO}" \
  --controller-host 127.0.0.1 \
  --controller-port "${CONTROLLER_OPENFLOW_PORT}"

multipass exec "${VM_NAME}" -- sudo python3 -u "${PERFORMANCE_SCENARIO}" \
  --controller-host 127.0.0.1 \
  --controller-port "${CONTROLLER_OPENFLOW_PORT}"

if [[ -n "$(multipass exec "${VM_NAME}" -- sudo ovs-vsctl list-br)" ]]; then
  echo "Stale OVS bridges remain after validation." >&2
  exit 1
fi

echo "Data-plane failover, host spoofing, and link performance validation passed."
