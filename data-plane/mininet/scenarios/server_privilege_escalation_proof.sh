#!/usr/bin/env bash
set -Eeuo pipefail

PROOF_DIR="/run/sdn-pe-lab"
PROOF_FILE="${PROOF_DIR}/proof.json"

if (($# != 0)); then
  echo "This proof helper does not accept arguments." >&2
  exit 64
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "The proof helper must run with effective UID 0." >&2
  exit 1
fi

umask 077
install -d -o root -g root -m 0700 "${PROOF_DIR}"

TEMP_PROOF="$(mktemp "${PROOF_DIR}/proof.XXXXXX")"
cleanup() {
  rm -f "${TEMP_PROOF}"
}
trap cleanup EXIT

TIMESTAMP="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
printf '%s\n' \
  '{' \
  '  "scenario": "SDN-PE-01",' \
  '  "effective_uid": 0,' \
  '  "effective_user": "root",' \
  "  \"timestamp\": \"${TIMESTAMP}\"" \
  '}' >"${TEMP_PROOF}"

chown root:root "${TEMP_PROOF}"
chmod 0600 "${TEMP_PROOF}"
mv -f "${TEMP_PROOF}" "${PROOF_FILE}"
trap - EXIT

echo "Privilege proof created at ${PROOF_FILE}"
