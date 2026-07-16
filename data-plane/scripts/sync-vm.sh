#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VM_NAME="${VM_NAME:-sdn-lab}"
VM_PROJECT_DIR="${VM_PROJECT_DIR:-/home/ubuntu/sdn-platform}"
REMOTE_ARCHIVE="/home/ubuntu/data-plane-source.tar.gz"
REMOTE_STAGE="/home/ubuntu/data-plane-sync-next"
REMOTE_BACKUP="/home/ubuntu/data-plane-sync-previous"
ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/data-plane.XXXXXX.tar.gz")"

if command -v shasum >/dev/null 2>&1; then
  HASH_COMMAND=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
  HASH_COMMAND=(sha256sum)
else
  echo "A SHA-256 command is required: shasum or sha256sum." >&2
  exit 1
fi

cleanup() {
  rm -f "${ARCHIVE}"
  multipass exec "${VM_NAME}" -- rm -f "${REMOTE_ARCHIVE}" \
    >/dev/null 2>&1 || true
  multipass exec "${VM_NAME}" -- sudo rm -rf "${REMOTE_STAGE}" \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! command -v multipass >/dev/null 2>&1; then
  echo "Multipass is not installed or is not available in PATH." >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "tar is not installed or is not available in PATH." >&2
  exit 1
fi

if ! multipass list --format csv | \
  awk -F, -v name="${VM_NAME}" 'NR > 1 && $1 == name {found=1} END {exit !found}'; then
  echo "Multipass instance does not exist: ${VM_NAME}" >&2
  exit 1
fi

multipass start "${VM_NAME}" >/dev/null 2>&1 || true

if ! multipass exec "${VM_NAME}" -- test -d "${VM_PROJECT_DIR}"; then
  echo "VM project directory does not exist: ${VM_PROJECT_DIR}" >&2
  exit 1
fi

build_host_manifest() {
  (
    cd "${REPO_ROOT}"
    find data-plane -type f \
      ! -path '*/__pycache__/*' \
      ! -path '*/.pytest_cache/*' \
      ! -name '*.pyc' \
      ! -name '.DS_Store' \
      -print | LC_ALL=C sort |
      while IFS= read -r file; do
        "${HASH_COMMAND[@]}" "${file}"
      done
  )
}

echo "Packing the current data-plane source..."
COPYFILE_DISABLE=1 tar \
  -czf "${ARCHIVE}" \
  --format=ustar \
  --exclude='*/__pycache__' \
  --exclude='*/.pytest_cache' \
  --exclude='*.pyc' \
  --exclude='.DS_Store' \
  -C "${REPO_ROOT}" data-plane

echo "Synchronizing data-plane into ${VM_NAME}:${VM_PROJECT_DIR}..."
multipass transfer "${ARCHIVE}" "${VM_NAME}:${REMOTE_ARCHIVE}"
multipass exec "${VM_NAME}" -- \
  sudo rm -rf "${REMOTE_STAGE}" "${REMOTE_BACKUP}"
multipass exec "${VM_NAME}" -- mkdir -p "${REMOTE_STAGE}"
multipass exec "${VM_NAME}" -- \
  tar -xzf "${REMOTE_ARCHIVE}" -C "${REMOTE_STAGE}"

if ! multipass exec "${VM_NAME}" -- \
  test -f "${REMOTE_STAGE}/data-plane/scripts/verify.sh"; then
  echo "Synchronized archive does not contain data-plane/scripts/verify.sh." >&2
  exit 1
fi

if multipass exec "${VM_NAME}" -- test -d "${VM_PROJECT_DIR}/data-plane"; then
  multipass exec "${VM_NAME}" -- \
    sudo mv "${VM_PROJECT_DIR}/data-plane" "${REMOTE_BACKUP}"
fi

if ! multipass exec "${VM_NAME}" -- \
  sudo mv "${REMOTE_STAGE}/data-plane" "${VM_PROJECT_DIR}/data-plane"; then
  if multipass exec "${VM_NAME}" -- test -d "${REMOTE_BACKUP}"; then
    multipass exec "${VM_NAME}" -- \
      sudo mv "${REMOTE_BACKUP}" "${VM_PROJECT_DIR}/data-plane"
  fi
  echo "Failed to activate the synchronized data-plane source." >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- sudo rm -rf "${REMOTE_STAGE}"

HOST_MANIFEST="$(build_host_manifest)"
VM_MANIFEST="$(
  multipass exec "${VM_NAME}" -- bash -c '
    set -Eeuo pipefail
    cd "$1"
    find data-plane -type f \
      ! -path "*/__pycache__/*" \
      ! -path "*/.pytest_cache/*" \
      ! -name "*.pyc" \
      ! -name ".DS_Store" \
      -print | LC_ALL=C sort |
      while IFS= read -r file; do
        sha256sum "$file"
      done
  ' _ "${VM_PROJECT_DIR}"
)"

if [[ "${HOST_MANIFEST}" != "${VM_MANIFEST}" ]]; then
  if multipass exec "${VM_NAME}" -- test -d "${REMOTE_BACKUP}"; then
    multipass exec "${VM_NAME}" -- sudo rm -rf "${VM_PROJECT_DIR}/data-plane"
    multipass exec "${VM_NAME}" -- \
      sudo mv "${REMOTE_BACKUP}" "${VM_PROJECT_DIR}/data-plane"
  fi
  echo "Data-plane source hash mismatch after VM synchronization." >&2
  exit 1
fi

multipass exec "${VM_NAME}" -- sudo rm -rf "${REMOTE_BACKUP}"
echo "Data-plane source synchronized and SHA-256 verified."
