#!/usr/bin/env bash
# =============================================================================
# start_benign_traffic.sh
# Continuously generates normal UE background traffic (ping, curl, iperf3)
# towards the OVS MEC UPF node to keep OVS flow tables and telemetry active.
# =============================================================================

set -u

TARGET_IP="${TARGET_IP:-10.200.0.10}"
HTTP_PORT="${HTTP_PORT:-8080}"
IPERF_PORT="${IPERF_PORT:-5201}"
INTERVAL_SEC="${INTERVAL_SEC:-2}"

echo "[INFO] Starting continuous benign UE traffic generator towards ${TARGET_IP}..."

cleanup() {
    echo "[INFO] Stopping benign traffic generator..."
    exit 0
}
trap cleanup SIGINT SIGTERM

while true; do
    TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "[${TIMESTAMP}] Sending benign ICMP echo requests to ${TARGET_IP}..."
    ping -c 3 -W 1 "${TARGET_IP}" >/dev/null 2>&1 || true

    echo "[${TIMESTAMP}] Performing benign HTTP GET request to http://${TARGET_IP}:${HTTP_PORT}/health..."
    curl -s -m 2 "http://${TARGET_IP}:${HTTP_PORT}/health" >/dev/null 2>&1 || true

    echo "[${TIMESTAMP}] Running short benign iperf3 bandwidth burst to ${TARGET_IP}:${IPERF_PORT}..."
    iperf3 -c "${TARGET_IP}" -p "${IPERF_PORT}" -t 1 -b 1M >/dev/null 2>&1 || true

    sleep "${INTERVAL_SEC}"
done
