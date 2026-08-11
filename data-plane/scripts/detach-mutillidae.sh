#!/usr/bin/env bash
set -Eeuo pipefail

VM_NAME="${VM_NAME:-sdn-lab}"
UNIT_NAME="sdn-mutillidae-relay"

if ! multipass list --format csv | \
  awk -F, -v name="${VM_NAME}" 'NR > 1 && $1 == name {found=1} END {exit !found}'; then
  echo "Multipass instance does not exist: ${VM_NAME}" >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- \
  sudo systemctl stop "${UNIT_NAME}" >/dev/null 2>&1 || true

echo "Mutillidae detached from the Mininet web host."
