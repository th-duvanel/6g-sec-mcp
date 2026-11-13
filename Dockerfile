# =============================================================================
# Multi-Stage Dockerfile for 6G-SEC-MCP Distributed Edge Experimentation
# Targets:
#   1. ovs-node    : Open vSwitch (UPF Simulator)
#   2. traffic-gen : Benign UE Traffic & Attack Vector Generator
#   3. agent-env   : Python 3.12 Slim AI & MCP IDS Execution Environment (Default)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: ovs-node (Open vSwitch MEC UPF Simulator)
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS ovs-node

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    openvswitch-switch \
    openvswitch-common \
    iproute2 \
    iputils-ping \
    iperf3 \
    python3 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/ovs_entrypoint.sh /usr/local/bin/ovs_entrypoint.sh
RUN chmod +x /usr/local/bin/ovs_entrypoint.sh

VOLUME ["/var/log/openvswitch", "/var/run/openvswitch"]
EXPOSE 8080 5201 6653

ENTRYPOINT ["/usr/local/bin/ovs_entrypoint.sh"]

# -----------------------------------------------------------------------------
# Stage 2: traffic-gen (UE Traffic & DDoS / Reconnaissance Attack Generator)
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS traffic-gen

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    iperf3 \
    hping3 \
    nmap \
    curl \
    slowhttptest \
    iputils-ping \
    iproute2 \
    python3 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts
COPY scripts/start_benign_traffic.sh /scripts/start_benign_traffic.sh
COPY scripts/attack_syn_flood.sh /scripts/attack_syn_flood.sh
COPY scripts/attack_slowloris.sh /scripts/attack_slowloris.sh
COPY scripts/attack_port_scan.sh /scripts/attack_port_scan.sh
RUN chmod +x /scripts/*.sh

CMD ["/scripts/start_benign_traffic.sh"]

# -----------------------------------------------------------------------------
# Stage 3: agent-env (AI & MCP IDS Execution Environment - Default Target)
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS agent-env

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    openvswitch-common \
    iproute2 \
    iputils-ping \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app/

CMD ["tail", "-f", "/dev/null"]
