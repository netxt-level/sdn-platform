#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "provision-ubuntu.sh must run as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

PACKAGES=(
  mininet
  openvswitch-switch
  openvswitch-common
  iperf3
  tcpdump
  iproute2
  iputils-ping
  curl
  jq
  ethtool
  net-tools
  python3-pip
  docker.io
  docker-compose-v2
  docker-buildx
)

apt-get update
apt-get install -y "${PACKAGES[@]}"

systemctl enable --now openvswitch-switch
systemctl enable --now docker

if id ubuntu >/dev/null 2>&1; then
  usermod -aG docker ubuntu
fi

echo "Environment packages are ready:"
mn --version
ovs-vsctl --version | head -n 1
docker --version
docker compose version
