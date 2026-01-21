#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "This script must be run as root (required for TUN/TAP access)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is required but was not found in PATH." >&2
  exit 1
fi

INTERFACE="${FORWARD_INTERFACE:-$(ip route get 1.1.1.1 2>/dev/null | awk 'NR==1 {print $5}')}"
INTERFACE="${INTERFACE%% }"
INTERFACE="${INTERFACE:-}"
if [[ -z "${INTERFACE}" ]]; then
  echo "Unable to determine outbound interface. Set FORWARD_INTERFACE explicitly." >&2
  exit 1
fi

TUN_NAME="${FORWARD_TUN:-utun8}"
LOG_LEVEL="${FORWARD_LOG_LEVEL:-info}"
DEST_HOST="${FORWARD_DEST:-1.0.0.1}"

TARGET_IP="$(getent ahostsv4 "${DEST_HOST}" 2>/dev/null | awk 'NR==1 {print $1}')"
if [[ -z "${TARGET_IP}" ]]; then
  echo "Failed to resolve ${DEST_HOST}." >&2
  exit 1
fi

cleanup() {
  set +e
  if [[ -n "${TARGET_IP}" ]]; then
    ip route del "${TARGET_IP}" dev "${TUN_NAME}" 2>/dev/null || true
  fi
  if [[ -n "${FORWARD_PID:-}" ]]; then
    kill "${FORWARD_PID}" 2>/dev/null || true
    wait "${FORWARD_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cargo build --example forward >/dev/null

"${REPO_ROOT}/target/debug/examples/forward" \
  --interface "${INTERFACE}" \
  --name "${TUN_NAME}" \
  --log-level "${LOG_LEVEL}" &
FORWARD_PID=$!

for _ in $(seq 1 20); do
  if ip link show "${TUN_NAME}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! ip link show "${TUN_NAME}" >/dev/null 2>&1; then
  echo "Timed out waiting for ${TUN_NAME} to appear." >&2
  exit 1
fi

ip addr flush dev "${TUN_NAME}" >/dev/null 2>&1 || true
ip addr add 10.10.10.2/24 dev "${TUN_NAME}"
ip link set "${TUN_NAME}" up
ip route replace "${TARGET_IP}" via 10.10.10.1 dev "${TUN_NAME}"

curl --verbose --interface "${TUN_NAME}" "http://${DEST_HOST}"
