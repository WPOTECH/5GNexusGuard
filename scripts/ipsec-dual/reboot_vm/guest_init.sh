#!/bin/bash
# guest_init.sh — Guest initialization script for KVM acceptance.
#
# Runs the guest agent acceptance tests and reports results.
# Does NOT modify host networking or kernel modules.
set -euo pipefail

GUEST_DIR="${1:-/sys/fs/bpf/atomic-test}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== 5GNexusGuard Guest Acceptance ==="
echo "pin_dir: ${GUEST_DIR}"

# Run the Python acceptance agent
exec python3 "${SCRIPT_DIR}/guest_agent.py" "${GUEST_DIR}"