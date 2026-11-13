#!/usr/bin/env bash
# =============================================================================
# attack_port_scan.sh
# Launches aggressive network reconnaissance against the OVS MEC node using nmap.
# =============================================================================

set -u

TARGET_IP="${1:-${TARGET_IP:-10.200.0.10}}"
PORT_RANGE="${2:-1-1024,5201,8080}"

echo "[ATTACK] Launching aggressive Nmap SYN/Service reconnaissance against ${TARGET_IP}..."
echo "[ATTACK] Port range: ${PORT_RANGE}"

nmap -sS -T4 -Pn -p "${PORT_RANGE}" --max-retries 1 "${TARGET_IP}" || true

echo "[ATTACK] Port scan reconnaissance completed."
