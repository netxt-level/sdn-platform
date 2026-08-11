#!/usr/bin/env bash
set -Eeuo pipefail

WEB_NAMESPACE_PID="${1:?web namespace PID is required}"
PROJECT_DIR="${2:-/home/ubuntu/sdn-platform}"
TARGET_PORT="${MUTILLIDAE_HOST_PORT:-8088}"
PROXY_SCRIPT="${PROJECT_DIR}/data-plane/mininet/tcp_proxy.py"
ROOT_PROXY_PID=""
WEB_PROXY_PID=""

cleanup() {
  if [[ -n "${WEB_PROXY_PID}" ]]; then
    kill "${WEB_PROXY_PID}" 2>/dev/null || true
    wait "${WEB_PROXY_PID}" 2>/dev/null || true
  fi
  if [[ -n "${ROOT_PROXY_PID}" ]]; then
    kill "${ROOT_PROXY_PID}" 2>/dev/null || true
    wait "${ROOT_PROXY_PID}" 2>/dev/null || true
  fi
  if ip link show mut-root0 >/dev/null 2>&1; then
    ip link delete mut-root0
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -e "/proc/${WEB_NAMESPACE_PID}/ns/net" ]]; then
  echo "Mininet web namespace does not exist: ${WEB_NAMESPACE_PID}" >&2
  exit 1
fi

if ip link show mut-root0 >/dev/null 2>&1; then
  echo "Mutillidae management interface already exists: mut-root0" >&2
  exit 1
fi

ip link add mut-root0 type veth peer name mut-web0
ip addr add 169.254.100.1/30 dev mut-root0
ip link set mut-root0 up
ip link set mut-web0 netns "${WEB_NAMESPACE_PID}"
nsenter -t "${WEB_NAMESPACE_PID}" -n \
  ip addr add 169.254.100.2/30 dev mut-web0
nsenter -t "${WEB_NAMESPACE_PID}" -n ip link set mut-web0 up

python3 "${PROXY_SCRIPT}" \
  --listen-host 169.254.100.1 \
  --listen-port 18080 \
  --target-host 127.0.0.1 \
  --target-port "${TARGET_PORT}" &
ROOT_PROXY_PID=$!

nsenter -t "${WEB_NAMESPACE_PID}" -n \
  python3 "${PROXY_SCRIPT}" \
  --listen-host 10.0.0.100 \
  --listen-port 80 \
  --target-host 169.254.100.1 \
  --target-port 18080 &
WEB_PROXY_PID=$!

while kill -0 "${WEB_NAMESPACE_PID}" 2>/dev/null \
  && kill -0 "${ROOT_PROXY_PID}" 2>/dev/null \
  && kill -0 "${WEB_PROXY_PID}" 2>/dev/null; do
  sleep 0.2
done
