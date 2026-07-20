#!/usr/bin/env bash
set -Eeuo pipefail

VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
SENSOR_INTERFACE="${SENSOR_INTERFACE:-sdn-sensor0}"
MIRROR_INTERFACE="${MIRROR_INTERFACE:-sdn-mirror0}"

if ! multipass list --format csv | \
  awk -F, -v name="${VM_NAME}" 'NR > 1 && $1 == name {found=1} END {exit !found}'; then
  echo "Multipass instance does not exist: ${VM_NAME}" >&2
  exit 1
fi

multipass start "${VM_NAME}" >/dev/null 2>&1 || true
multipass exec "${VM_NAME}" -- sudo python3 \
  "${VM_PROJECT_DIR}/data-plane/mininet/sensor.py" setup \
  --sensor-interface "${SENSOR_INTERFACE}" \
  --mirror-interface "${MIRROR_INTERFACE}"

echo "Sensor veth is ready: ${SENSOR_INTERFACE} <-> ${MIRROR_INTERFACE}"
