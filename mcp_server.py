"""Model Context Protocol (MCP) Server for 6G MEC Intrusion Detection & Mitigation.

Enforces strict local Client-Server isolation:
1. Reads raw Open vSwitch logs exclusively through `OVSAdapter`.
2. Filters background UE noise and exposes a compact, token-efficient JSON
   Resource (`telemetry://ovs/aggregated_flows`).
3. Exposes ONLY ONE Tool: `block_ip(target_ip: str)`.
4. Acts as a security Sandbox enforcing Role-Based Access Control (RBAC),
   strict IPv4 regex validation, and protected-infrastructure whitelisting
   before delegating mitigation actuation to `OVSAdapter`.
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import logging
import os
import re
import sys
import time
from typing import Any, Callable

from network_adapter import MitigationResult, NetworkAdapter, OVSAdapter, load_dotenv

MCP_PROTOCOL_VERSION: str = "2024-11-05"
MCP_SERVER_NAME: str = "6G-SEC-MCP-Controller"
MCP_SERVER_VERSION: str = "1.0.0"

try:
    from mcp.types import (
        Implementation,
        InitializeResult,
        ResourcesCapability,
        ServerCapabilities,
        ToolsCapability,
    )

    _HAS_MCP_TYPES = True
except ImportError:
    _HAS_MCP_TYPES = False


def build_initialize_result(
    server_name: str = MCP_SERVER_NAME,
    server_version: str = MCP_SERVER_VERSION,
    protocol_version: str = MCP_PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Construct an MCP-compliant `InitializeResult` payload for client handshakes.

    Explicitly provides `protocolVersion`, `capabilities`, and `serverInfo`
    satisfying the official MCP Pydantic `InitializeResult` validation schema.

    Args:
        server_name: Reported MCP server identifier.
        server_version: Reported MCP server version string.
        protocol_version: Negotiated MCP protocol version (default `"2024-11-05"`).

    Returns:
        Dictionary matching the `InitializeResult` JSON-RPC result schema.
    """
    resolved_version = protocol_version or MCP_PROTOCOL_VERSION

    if _HAS_MCP_TYPES:
        init_obj = InitializeResult(
            protocolVersion=resolved_version,
            capabilities=ServerCapabilities(
                resources=ResourcesCapability(subscribe=False, listChanged=False),
                tools=ToolsCapability(listChanged=False),
            ),
            serverInfo=Implementation(
                name=server_name,
                version=server_version,
            ),
        )
        return init_obj.model_dump(by_alias=True, exclude_none=True)

    return {
        "protocolVersion": resolved_version,
        "capabilities": {
            "resources": {
                "subscribe": False,
                "listChanged": False,
            },
            "tools": {
                "listChanged": False,
            },
        },
        "serverInfo": {
            "name": server_name,
            "version": server_version,
        },
    }


def _build_tool_input_schema(func: Callable[..., Any]) -> dict[str, Any]:
    """Generate a valid JSON Schema `inputSchema` object for an exposed MCP tool."""
    sig = inspect.signature(func)
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param_name, param in sig.parameters.items():
        properties[param_name] = {
            "type": "string",
            "description": f"Parameter '{param_name}' for tool '{func.__name__}'.",
        }
        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


try:
    from mcp.server.fastmcp import FastMCP
except ImportError:

    class FastMCP:  # type: ignore[no-redef]
        """MCP JSON-RPC 2.0 stdio server compliant with official MCP Pydantic schemas."""

        def __init__(self, name: str, version: str = MCP_SERVER_VERSION) -> None:
            self.name: str = name
            self.version: str = version
            self._resources: dict[str, Callable[[], str]] = {}
            self._tools: dict[str, Callable[..., str]] = {}

        def resource(self, uri: str) -> Callable[[Callable[[], str]], Callable[[], str]]:
            """Register a read-only MCP resource handler by URI."""

            def decorator(func: Callable[[], str]) -> Callable[[], str]:
                self._resources[uri] = func
                return func

            return decorator

        def tool(self) -> Callable[[Callable[..., str]], Callable[..., str]]:
            """Register an MCP tool handler by function name."""

            def decorator(func: Callable[..., str]) -> Callable[..., str]:
                self._tools[func.__name__] = func
                return func

            return decorator

        def run(self, transport: str = "stdio") -> None:
            """Run the JSON-RPC 2.0 loop over standard input/output."""
            del transport
            for raw_line in sys.stdin:
                line = raw_line.strip()
                if not line:
                    continue
                req_id: Any = None
                try:
                    req = json.loads(line)
                    req_id = req.get("id")
                    method = str(req.get("method", ""))
                    params = req.get("params", {}) or {}

                    # JSON-RPC notifications (e.g. "notifications/initialized") have no id
                    if req_id is None or method.startswith("notifications/"):
                        continue

                    if method == "initialize":
                        client_proto = str(
                            params.get("protocolVersion") or MCP_PROTOCOL_VERSION
                        )
                        result: Any = build_initialize_result(
                            server_name=self.name,
                            server_version=self.version,
                            protocol_version=client_proto,
                        )
                    elif method == "ping":
                        result = {}
                    elif method == "tools/list":
                        result = {
                            "tools": [
                                {
                                    "name": name,
                                    "description": (fn.__doc__ or "").strip(),
                                    "inputSchema": _build_tool_input_schema(fn),
                                }
                                for name, fn in self._tools.items()
                            ]
                        }
                    elif method == "resources/list":
                        result = {
                            "resources": [
                                {
                                    "uri": uri,
                                    "name": uri.rsplit("/", 1)[-1] or uri,
                                    "description": (fn.__doc__ or "").strip(),
                                    "mimeType": "application/json",
                                }
                                for uri, fn in self._resources.items()
                            ]
                        }
                    elif method == "resources/read":
                        uri = str(params.get("uri", ""))
                        text = self._resources[uri]() if uri in self._resources else "{}"
                        result = {
                            "contents": [
                                {
                                    "uri": uri,
                                    "mimeType": "application/json",
                                    "text": text,
                                }
                            ]
                        }
                    elif method == "tools/call":
                        tname = str(params.get("name", ""))
                        targs = params.get("arguments", {}) or {}
                        out = self._tools[tname](**targs) if tname in self._tools else "{}"
                        result = {
                            "content": [{"type": "text", "text": out}],
                            "isError": False,
                        }
                    else:
                        result = {}

                    sys.stdout.write(
                        json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n"
                    )
                    sys.stdout.flush()
                except Exception as exc:
                    if req_id is not None:
                        sys.stdout.write(
                            json.dumps(
                                {
                                    "jsonrpc": "2.0",
                                    "id": req_id,
                                    "error": {"code": -32603, "message": str(exc)},
                                }
                            )
                            + "\n"
                        )
                        sys.stdout.flush()


load_dotenv()

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] [MCP-SERVER] %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize FastMCP Server
mcp = FastMCP(MCP_SERVER_NAME)

# Strict IPv4 validation pattern (blocks any command injection tokens or CIDR abuse)
IPV4_STRICT_REGEX: re.Pattern[str] = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)

AUTHORIZED_RBAC_ROLES: frozenset[str] = frozenset(
    {"sec_operator_mec", "ids_autonomous_agent", "mec_security_admin"}
)


def _get_adapter() -> NetworkAdapter:
    """Instantiate the configured `OVSAdapter`."""
    return OVSAdapter()


def _get_protected_ips() -> set[str]:
    """Return the set of protected infrastructure IPs that must never be blocked."""
    raw_list = os.getenv("PROTECTED_IPS", "127.0.0.1,10.200.0.1,10.200.0.2,10.200.0.10")
    protected = {ip.strip() for ip in raw_list.split(",") if ip.strip()}
    protected.update({"127.0.0.1", "0.0.0.0", "10.200.0.1", "10.200.0.10"})
    return protected


def aggregate_and_filter_telemetry(
    raw_telemetry: str,
    protected_ips: set[str] | None = None,
) -> dict[str, Any]:
    """Parse raw OVS flow logs, filter out benign background noise, and aggregate by source IP.

    Args:
        raw_telemetry: Raw multi-line string from `OVSAdapter.get_telemetry_stream()`.
        protected_ips: Infrastructure IPs to annotate as protected.

    Returns:
        Compact dictionary suitable for JSON serialization via the MCP Resource.
    """
    protected = protected_ips if protected_ips is not None else _get_protected_ips()
    per_source: dict[str, dict[str, Any]] = {}
    total_raw_lines = 0
    filtered_noise_lines = 0

    for line in raw_telemetry.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("===") or stripped.startswith("NXST_FLOW"):
            continue

        total_raw_lines += 1

        # Ignore already-installed drop rules
        if "actions=drop" in stripped.lower():
            filtered_noise_lines += 1
            continue

        src_match = re.search(r"nw_src=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", stripped)
        if not src_match:
            filtered_noise_lines += 1
            continue

        src_ip = src_match.group(1)
        if src_ip in protected:
            filtered_noise_lines += 1
            continue

        pkt_match = re.search(r"n_packets=(\d+)", stripped)
        byte_match = re.search(r"n_bytes=(\d+)", stripped)
        dst_port_match = re.search(r"tp_dst=(\d+)", stripped)
        proto_match = re.search(r"proto=([a-zA-Z0-9_-]+)", stripped)

        packets = int(pkt_match.group(1)) if pkt_match else 1
        byte_count = int(byte_match.group(1)) if byte_match else 64
        dst_port = int(dst_port_match.group(1)) if dst_port_match else 0
        proto = proto_match.group(1).lower() if proto_match else "ip"
        is_syn = "syn-recv" in stripped.lower() or "tcp_flags=syn" in stripped.lower()
        is_estab_http = dst_port == 8080 and "estab" in stripped.lower()

        bucket = per_source.setdefault(
            src_ip,
            {
                "src_ip": src_ip,
                "flow_count": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "syn_flow_count": 0,
                "http_concurrent_flows": 0,
                "dst_ports": set(),
                "protocols": set(),
            },
        )
        bucket["flow_count"] += 1
        bucket["total_packets"] += packets
        bucket["total_bytes"] += byte_count
        if is_syn:
            bucket["syn_flow_count"] += 1
        if is_estab_http:
            bucket["http_concurrent_flows"] += 1
        if dst_port > 0:
            bucket["dst_ports"].add(dst_port)
        bucket["protocols"].add(proto)

    suspicious_sources: list[dict[str, Any]] = []
    for src_ip, stats in per_source.items():
        unique_ports = len(stats["dst_ports"])
        indicators: list[str] = []

        if stats["syn_flow_count"] >= 2 or stats["total_packets"] >= 1000:
            indicators.append("TCP_SYN_FLOOD")
        if unique_ports >= 5:
            indicators.append("PORT_SCAN_RECON")
        if stats["http_concurrent_flows"] >= 10 or stats["flow_count"] >= 15:
            indicators.append("SLOWLORIS_LOW_RATE_DDOS")

        # Filter out low-rate benign UE traffic that triggers no anomaly indicators
        if not indicators and stats["total_packets"] < 250 and stats["flow_count"] <= 3:
            filtered_noise_lines += stats["flow_count"]
            continue

        suspicious_sources.append(
            {
                "src_ip": src_ip,
                "flow_count": stats["flow_count"],
                "total_packets": stats["total_packets"],
                "total_bytes": stats["total_bytes"],
                "syn_flow_count": stats["syn_flow_count"],
                "unique_dst_ports": unique_ports,
                "protocols": sorted(stats["protocols"]),
                "threat_indicators": indicators or ["ELEVATED_TRAFFIC_VOLUME"],
            }
        )

    suspicious_sources.sort(
        key=lambda item: (item["total_packets"], item["flow_count"]),
        reverse=True,
    )

    return {
        "schema_version": "1.0",
        "mec_node_bridge": os.getenv("OVS_BRIDGE", "br0"),
        "raw_lines_inspected": total_raw_lines,
        "noise_lines_filtered": filtered_noise_lines,
        "anomalous_sources": suspicious_sources,
    }


def validate_sandbox_policy(target_ip: str, role: str | None = None) -> tuple[bool, str]:
    """Enforce MCP Sandbox RBAC, strict regex validation, and IP whitelisting.

    Args:
        target_ip: Candidate IPv4 address requested for blocking.
        role: Active agent role identifier.

    Returns:
        Tuple of `(is_allowed, reason)`.
    """
    active_role = (role or os.getenv("MCP_AGENT_ROLE", "sec_operator_mec")).strip()
    if active_role not in AUTHORIZED_RBAC_ROLES:
        return (
            False,
            f"RBAC denial: role '{active_role}' is not authorized to invoke block_ip.",
        )

    candidate = target_ip.strip()
    if not IPV4_STRICT_REGEX.match(candidate):
        return (
            False,
            f"Regex sandbox violation: '{candidate}' is not a valid strict IPv4 address.",
        )

    try:
        ip_obj = ipaddress.IPv4Address(candidate)
    except ipaddress.AddressValueError as exc:
        return False, f"Invalid IPv4 address structure: {exc}"

    if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
        return (
            False,
            f"Sandbox policy violation: special/reserved IP '{candidate}' cannot be blocked.",
        )

    protected_ips = _get_protected_ips()
    if candidate in protected_ips:
        return (
            False,
            f"Sandbox policy violation: '{candidate}' is a protected MEC infrastructure IP.",
        )

    allowed_subnet = os.getenv("MCP_ALLOWED_SUBNET", "").strip()
    if allowed_subnet:
        try:
            subnet_net = ipaddress.IPv4Network(allowed_subnet, strict=False)
            if ip_obj not in subnet_net:
                return (
                    False,
                    f"Sandbox scope violation: '{candidate}' is outside managed subnet {subnet_net}.",
                )
        except ValueError:
            pass

    return True, "Sandbox RBAC and IPv4 validation passed."


@mcp.resource("telemetry://ovs/aggregated_flows")
def get_aggregated_flows_resource() -> str:
    """Expose filtered and aggregated OVS telemetry as a compact JSON MCP Resource."""
    adapter = _get_adapter()
    max_lines = int(os.getenv("TELEMETRY_TAIL_LINES", "50"))
    raw_logs = adapter.get_telemetry_stream(max_lines=max_lines)
    aggregated = aggregate_and_filter_telemetry(raw_logs)
    return json.dumps(aggregated, separators=(",", ":"))


@mcp.tool()
def block_ip(target_ip: str) -> str:
    """Block a malicious source IPv4 address at the MEC Open vSwitch data plane.

    Acts as a security Sandbox performing RBAC authorization, strict IPv4 regex
    validation, and protected-IP verification before triggering `OVSAdapter`.

    Args:
        target_ip: The IPv4 address of the attacking node to block (e.g., "10.200.0.20").

    Returns:
        JSON string detailing sandbox authorization, adapter execution status, and latency.
    """
    sandbox_start_ns = time.perf_counter()
    allowed, reason = validate_sandbox_policy(target_ip=target_ip)

    if not allowed:
        sandbox_ms = (time.perf_counter() - sandbox_start_ns) * 1000.0
        logger.warning("MCP Sandbox rejected block_ip(%s): %s", target_ip, reason)
        return json.dumps(
            {
                "success": False,
                "target_ip": target_ip,
                "sandbox_authorized": False,
                "sandbox_reason": reason,
                "command_executed": "BLOCKED_BY_MCP_SANDBOX",
                "adapter_execution_ms": round(sandbox_ms, 4),
            },
            separators=(",", ":"),
        )

    adapter = _get_adapter()
    result: MitigationResult = adapter.block_source_ip(target_ip=target_ip.strip())
    total_tool_ms = (time.perf_counter() - sandbox_start_ns) * 1000.0

    return json.dumps(
        {
            "success": result.success,
            "target_ip": target_ip.strip(),
            "sandbox_authorized": True,
            "sandbox_reason": reason,
            "command_executed": result.command_executed,
            "adapter_execution_ms": round(result.execution_time_ms, 4),
            "tool_total_ms": round(total_tool_ms, 4),
            "simulated": result.simulated,
        },
        separators=(",", ":"),
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
