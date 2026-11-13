#!/usr/bin/env bash
# =============================================================================
# ovs_entrypoint.sh
# Initializes Open vSwitch (OVS) simulating a 5G/6G MEC UPF switch, starts
# target services (iperf3, HTTP health server), and exports flow telemetry logs
# to /var/log/openvswitch/ovs_telemetry.log.
# =============================================================================

set -u

OVS_BRIDGE="${OVS_BRIDGE:-br0}"
LOG_DIR="/var/log/openvswitch"
RUN_DIR="/var/run/openvswitch"
DB_DIR="/etc/openvswitch"
TELEMETRY_LOG="${LOG_DIR}/ovs_telemetry.log"

mkdir -p "${LOG_DIR}" "${RUN_DIR}" "${DB_DIR}"
touch "${TELEMETRY_LOG}"

echo "[OVS-NODE] Initializing Open vSwitch database and daemons..."

if [ ! -f "${DB_DIR}/conf.db" ]; then
    ovsdb-tool create "${DB_DIR}/conf.db" /usr/share/openvswitch/vswitch.ovsschema
fi

ovsdb-server "${DB_DIR}/conf.db" \
    --remote=punix:"${RUN_DIR}/db.sock" \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile="${RUN_DIR}/ovsdb-server.pid" \
    --log-file="${LOG_DIR}/ovsdb-server.log" \
    --detach

ovs-vsctl --no-wait init

ovs-vswitchd unix:"${RUN_DIR}/db.sock" \
    --pidfile="${RUN_DIR}/ovs-vswitchd.pid" \
    --log-file="${LOG_DIR}/ovs-vswitchd.log" \
    --detach

# Create OVS bridge (fallback to netdev userspace datapath in containers without openvswitch kernel module)
ovs-vsctl --may-exist add-br "${OVS_BRIDGE}" -- set bridge "${OVS_BRIDGE}" datapath_type=netdev || \
    ovs-vsctl --may-exist add-br "${OVS_BRIDGE}"

ovs-ofctl add-flow "${OVS_BRIDGE}" "priority=1,actions=normal" || true

# Start UPF target services (iperf3 server and lightweight HTTP responder on port 8080)
iperf3 -s -p 5201 -D >/dev/null 2>&1 || true
python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 &

echo "[OVS-NODE] Open vSwitch bridge '${OVS_BRIDGE}' active. Writing flow telemetry to ${TELEMETRY_LOG}..."

# Continuous telemetry collector combining OVS OpenFlow counters and live ingress flow telemetry
while true; do
    TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    {
        echo "=== OVS_TELEMETRY_SNAPSHOT timestamp=${TS} bridge=${OVS_BRIDGE} ==="
        ovs-ofctl dump-flows "${OVS_BRIDGE}" 2>/dev/null || true
        # Capture active TCP/ICMP socket/packet states formatted as OpenFlow telemetry lines
        ss -ntu state all 2>/dev/null | awk -v ts="${TS}" '
        NR>1 {
            split($5, local_addr, ":");
            split($6, peer_addr, ":");
            src_ip = peer_addr[1];
            dst_ip = local_addr[1];
            dst_port = local_addr[2];
            src_port = peer_addr[2];
            if (src_ip != "" && src_ip != "*" && src_ip != "127.0.0.1") {
                printf "cookie=0x0, duration=1.0s, table=0, n_packets=1, n_bytes=64, timestamp=%s, proto=%s, state=%s, nw_src=%s, tp_src=%s, nw_dst=%s, tp_dst=%s actions=NORMAL\n", ts, $1, $2, src_ip, src_port, dst_ip, dst_port
            }
        }'
    } >> "${TELEMETRY_LOG}"

    # Keep telemetry log bounded so disk does not fill during long runs
    if [ "$(wc -l < "${TELEMETRY_LOG}")" -gt 5000 ]; then
        tail -n 2000 "${TELEMETRY_LOG}" > "${TELEMETRY_LOG}.tmp" && mv "${TELEMETRY_LOG}.tmp" "${TELEMETRY_LOG}"
    fi

    sleep 1
done
