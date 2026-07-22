#!/usr/bin/env bash
set -Eeuo pipefail

VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
MUTILLIDAE_HOST_PORT="${MUTILLIDAE_HOST_PORT:-8088}"
UNIT_NAME="sdn-mutillidae-relay"

if ! multipass list --format csv | \
  awk -F, -v name="${VM_NAME}" 'NR > 1 && $1 == name {found=1} END {exit !found}'; then
  echo "Multipass instance does not exist: ${VM_NAME}" >&2
  exit 1
fi

if multipass exec "${VM_NAME}" -- \
  sudo systemctl is-active --quiet "${UNIT_NAME}"; then
  echo "Mutillidae is already attached to the running Mininet web host."
  exit 0
fi

multipass exec "${VM_NAME}" -- \
  curl --fail --silent --show-error --output /dev/null \
  --header 'Host: mutillidae.localhost' \
  "http://127.0.0.1:${MUTILLIDAE_HOST_PORT}/"

WEB_PID="$(
  multipass exec "${VM_NAME}" -- ps -eo pid=,args= | \
    awk '$0 ~ /bash --norc --noediting -is mininet:web$/ {print $1}'
)"

if [[ -z "${WEB_PID}" ]] || [[ "${WEB_PID}" == *$'\n'* ]]; then
  echo "Expected exactly one running Mininet web namespace." >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- \
  sudo systemctl reset-failed "${UNIT_NAME}" >/dev/null 2>&1 || true
multipass exec "${VM_NAME}" -- \
  sudo env MUTILLIDAE_HOST_PORT="${MUTILLIDAE_HOST_PORT}" \
  systemd-run \
  --unit="${UNIT_NAME}" \
  --property=Type=simple \
  --property=Restart=no \
  "${VM_PROJECT_DIR}/data-plane/web/mutillidae/runtime-relay.sh" \
  "${WEB_PID}" \
  "${VM_PROJECT_DIR}" >/dev/null

for _ in {1..50}; do
  if multipass exec "${VM_NAME}" -- \
    sudo systemctl is-active --quiet "${UNIT_NAME}"; then
    echo "Mutillidae attached: h1/h2/h3 -> web 10.0.0.100:80"
    exit 0
  fi
  sleep 0.1
done

multipass exec "${VM_NAME}" -- \
  sudo journalctl --unit "${UNIT_NAME}" --no-pager --lines 30 >&2
exit 1
