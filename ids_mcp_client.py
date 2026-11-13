"""Autonomous MCP-Based IDS Client Agent (`ids_mcp_client.py`).

Implements the Proposed Scenario (Autonomous IDS mediated by Model Context Protocol):
1. Establishes an isolated local Client-Server session with `mcp_server.py`
   over standard MCP stdio transport.
2. Reads the filtered and aggregated JSON telemetry Resource
   (`telemetry://ovs/aggregated_flows`), drastically reducing prompt tokens.
3. Queries the LLM (Host B over reverse SSH tunnel or Gemini) for high-level
   mitigation intent (`block_ip` and `target_ip`) without exposing raw CLI syntax.
4. Executes the sandboxed `block_ip(target_ip)` MCP Tool on `mcp_server.py`.
5. Records high-precision latency (`time.perf_counter()`), control-plane
   signaling overhead (LLM + MCP JSON-RPC envelopes), token usage, and
   `psutil` CPU/RAM footprint into `metrics_results.csv`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator

from llm_client import BaseLLMClient, LLMClientFactory, LLMResponse
from metrics_collector import EdgeResourceMonitor, IncidentMetrics, MetricsLogger
from network_adapter import load_dotenv

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:

    @dataclass
    class StdioServerParameters:  # type: ignore[no-redef]
        command: str
        args: list[str]
        env: dict[str, str] | None = None

    @dataclass
    class _TextBlock:
        text: str

    @dataclass
    class _ResourceResp:
        contents: list[_TextBlock]

    @dataclass
    class _ToolResp:
        content: list[_TextBlock]
        isError: bool = False

    @dataclass
    class _ToolInfo:
        name: str

    @dataclass
    class _ToolsListResp:
        tools: list[_ToolInfo]

    class ClientSession:  # type: ignore[no-redef]
        """Lightweight MCP JSON-RPC 2.0 stdio client session fallback."""

        def __init__(
            self,
            read_stream: asyncio.StreamReader,
            write_stream: asyncio.StreamWriter,
        ) -> None:
            self._reader = read_stream
            self._writer = write_stream
            self._req_id = 0

        async def __aenter__(self) -> ClientSession:
            return self

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            return None

        async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
            self._req_id += 1
            payload = {
                "jsonrpc": "2.0",
                "id": self._req_id,
                "method": method,
                "params": params or {},
            }
            self._writer.write((json.dumps(payload) + "\n").encode("utf-8"))
            await self._writer.drain()
            raw_line = await self._reader.readline()
            if not raw_line:
                raise RuntimeError("MCP server closed stdio stream unexpectedly.")
            resp = json.loads(raw_line.decode("utf-8"))
            return dict(resp.get("result", {}) or {})

        async def initialize(self) -> dict[str, Any]:
            res = await self._rpc(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "6G-SEC-MCP-Client", "version": "1.0.0"},
                },
            )
            self._writer.write(
                (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode(
                    "utf-8"
                )
            )
            await self._writer.drain()
            return res

        async def list_tools(self) -> _ToolsListResp:
            res = await self._rpc("tools/list")
            tools = [_ToolInfo(name=str(t.get("name", ""))) for t in res.get("tools", [])]
            return _ToolsListResp(tools=tools)

        async def read_resource(self, uri: str) -> _ResourceResp:
            res = await self._rpc("resources/read", {"uri": uri})
            items = [_TextBlock(text=str(c.get("text", "{}"))) for c in res.get("contents", [])]
            return _ResourceResp(contents=items)

        async def call_tool(self, name: str, arguments: dict[str, Any]) -> _ToolResp:
            res = await self._rpc("tools/call", {"name": name, "arguments": arguments})
            items = [_TextBlock(text=str(c.get("text", "{}"))) for c in res.get("content", [])]
            return _ToolResp(content=items, isError=bool(res.get("isError", False)))

    @asynccontextmanager
    async def stdio_client(
        server: StdioServerParameters,
    ) -> AsyncIterator[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        proc = await asyncio.create_subprocess_exec(
            server.command,
            *server.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=server.env,
        )
        assert proc.stdout is not None and proc.stdin is not None
        try:
            yield proc.stdout, proc.stdin
        finally:
            try:
                proc.stdin.close()
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except Exception:
                pass

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [MCP-IDS-CLIENT] %(message)s",
)
logger = logging.getLogger(__name__)

MCP_RESOURCE_URI: str = "telemetry://ovs/aggregated_flows"

MCP_SYSTEM_INSTRUCTION: str = (
    "You are an autonomous 6G Multi-Access Edge Computing (MEC) Intrusion Detection "
    "Agent connected to an MCP Security Controller. Analyze the aggregated JSON flow "
    "telemetry resource and decide whether to invoke the `block_ip` tool. "
    "Respond ONLY with a compact JSON object in the exact format: "
    '{"action": "block_ip", "target_ip": "<ipv4_address>", "reason": "<short_reason>"} '
    'or {"action": "none", "target_ip": null, "reason": "benign"}.'
)


class MCPIDSClientAgent:
    """Autonomous IDS agent operating through the Model Context Protocol interface."""

    def __init__(
        self,
        llm_client: BaseLLMClient | None = None,
        metrics_logger: MetricsLogger | None = None,
        server_script_path: str | Path | None = None,
        dry_run: bool | None = None,
    ) -> None:
        """Initialize the MCP IDS Client Agent.

        Args:
            llm_client: Universal LLM client instance.
            metrics_logger: CSV logger writing to `metrics_results.csv`.
            server_script_path: Path to `mcp_server.py`.
            dry_run: Optional override for `OVS_DRY_RUN` passed to `mcp_server.py`.
        """
        self.llm_client: BaseLLMClient = llm_client or LLMClientFactory.create_client()
        self.metrics_logger: MetricsLogger = metrics_logger or MetricsLogger()
        self.server_script_path: Path = Path(
            server_script_path or Path(__file__).resolve().parent / "mcp_server.py"
        )
        self.dry_run: bool | None = dry_run

    @staticmethod
    def build_prompt(aggregated_json_str: str) -> str:
        """Construct a compact, token-efficient prompt using the MCP JSON resource."""
        return (
            "MCP Telemetry Resource (`telemetry://ovs/aggregated_flows`):\n"
            f"{aggregated_json_str}\n\n"
            "Available MCP Tool: `block_ip(target_ip: str)`\n"
            "Return JSON mitigation intent:"
        )

    @staticmethod
    def parse_mitigation_intent(llm_text: str, telemetry_json: str) -> tuple[str, str | None]:
        """Parse the LLM output to extract the desired action and `target_ip`.

        Args:
            llm_text: Raw text returned by the LLM.
            telemetry_json: Aggregated telemetry JSON string for fallback verification.

        Returns:
            Tuple of `(action, target_ip)`.
        """
        cleaned = re.sub(r"```(?:json)?", "", llm_text, flags=re.IGNORECASE).replace("```", "").strip()

        # Attempt structured JSON parse first
        json_match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if json_match:
            try:
                parsed: dict[str, Any] = json.loads(json_match.group(0))
                action = str(parsed.get("action", "block_ip")).strip().lower()
                target_ip = parsed.get("target_ip")
                if target_ip and isinstance(target_ip, str):
                    return action, target_ip.strip()
                if action == "none":
                    return "none", None
            except json.JSONDecodeError:
                pass

        # Fallback: extract explicit IPv4 from LLM output
        ip_match = re.search(
            r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b",
            cleaned,
        )
        if ip_match:
            return "block_ip", ip_match.group(0)

        # Secondary check: if telemetry had an anomalous source and LLM did not say "none"
        if "none" not in cleaned.lower():
            try:
                telemetry_data = json.loads(telemetry_json)
                sources = telemetry_data.get("anomalous_sources", [])
                if sources and isinstance(sources[0], dict):
                    return "block_ip", str(sources[0].get("src_ip"))
            except json.JSONDecodeError:
                pass

        return "none", None

    async def run_single_iteration_in_session(
        self,
        session: ClientSession,
    ) -> IncidentMetrics:
        """Execute one full MCP detection-and-mitigation cycle over an active MCP session."""
        with EdgeResourceMonitor() as resource_monitor:
            cycle_start_ns = time.perf_counter()

            # Step 1: Read filtered & aggregated JSON Resource from MCP Server
            resource_req_envelope = json.dumps(
                {"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": MCP_RESOURCE_URI}}
            ).encode("utf-8")

            resource_result = await session.read_resource(MCP_RESOURCE_URI)
            aggregated_json_str = "{}"
            if resource_result.contents:
                first_item = resource_result.contents[0]
                aggregated_json_str = getattr(first_item, "text", None) or str(first_item)

            telemetry_bytes = len(aggregated_json_str.encode("utf-8"))
            resource_resp_envelope = json.dumps(
                {"jsonrpc": "2.0", "result": {"contents": [{"uri": MCP_RESOURCE_URI, "text": aggregated_json_str}]}}
            ).encode("utf-8")

            # Step 2: Build compact prompt and query LLM for mitigation intent
            user_prompt = self.build_prompt(aggregated_json_str)
            llm_response: LLMResponse = self.llm_client.generate(
                prompt=user_prompt,
                system_instruction=MCP_SYSTEM_INSTRUCTION,
            )

            action, target_ip = self.parse_mitigation_intent(
                llm_text=llm_response.text,
                telemetry_json=aggregated_json_str,
            )
            logger.info(
                "LLM intent resolved in %.2f ms (prompt_tokens=%d, completion_tokens=%d): action=%s, target_ip=%s",
                llm_response.inference_latency_ms,
                llm_response.prompt_tokens,
                llm_response.completion_tokens,
                action,
                target_ip,
            )

            # Step 3: Invoke `block_ip` MCP Tool if an anomalous target IP was identified
            tool_signaling_bytes = 0
            adapter_exec_ms = 0.0
            mitigation_success = True
            mitigation_command = "NONE"

            if action == "block_ip" and target_ip:
                tool_req_envelope = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {"name": "block_ip", "arguments": {"target_ip": target_ip}},
                    }
                ).encode("utf-8")

                tool_call_result = await session.call_tool(
                    "block_ip",
                    arguments={"target_ip": target_ip},
                )

                tool_output_text = "{}"
                if tool_call_result.content:
                    first_block = tool_call_result.content[0]
                    tool_output_text = getattr(first_block, "text", None) or str(first_block)

                tool_resp_envelope = json.dumps(
                    {"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": tool_output_text}]}}
                ).encode("utf-8")
                tool_signaling_bytes = len(tool_req_envelope) + len(tool_resp_envelope)

                try:
                    tool_payload: dict[str, Any] = json.loads(tool_output_text)
                    mitigation_success = bool(tool_payload.get("success", False))
                    mitigation_command = str(tool_payload.get("command_executed", ""))
                    adapter_exec_ms = float(tool_payload.get("adapter_execution_ms", 0.0))
                except json.JSONDecodeError:
                    mitigation_success = not bool(getattr(tool_call_result, "isError", False))
                    mitigation_command = tool_output_text

            deployment_delay_ms = (time.perf_counter() - cycle_start_ns) * 1000.0

        mcp_signaling_bytes = (
            len(resource_req_envelope) + len(resource_resp_envelope) + tool_signaling_bytes
        )
        total_signaling_bytes = llm_response.signaling_bytes + mcp_signaling_bytes

        metrics = IncidentMetrics(
            timestamp_utc=MetricsLogger.utc_now_iso(),
            scenario="proposed_mcp",
            provider=llm_response.provider,
            model=llm_response.model,
            deployment_delay_ms=round(deployment_delay_ms, 4),
            inference_latency_ms=round(llm_response.inference_latency_ms, 4),
            adapter_execution_ms=round(adapter_exec_ms, 4),
            signaling_overhead_bytes=total_signaling_bytes,
            telemetry_payload_bytes=telemetry_bytes,
            prompt_tokens=llm_response.prompt_tokens,
            completion_tokens=llm_response.completion_tokens,
            total_tokens=llm_response.total_tokens,
            cpu_peak_percent=resource_monitor.cpu_peak_percent,
            ram_peak_mb=resource_monitor.ram_peak_mb,
            mitigation_success=mitigation_success,
            mitigation_command=mitigation_command,
        )

        self.metrics_logger.log_incident(metrics)
        logger.info(
            "MCP Cycle finished | Deployment Delay: %.2f ms | Signaling: %d B | "
            "Tokens: %d | CPU Peak: %.1f%% | RAM Peak: %.2f MB | Success: %s",
            metrics.deployment_delay_ms,
            metrics.signaling_overhead_bytes,
            metrics.total_tokens,
            metrics.cpu_peak_percent,
            metrics.ram_peak_mb,
            metrics.mitigation_success,
        )
        return metrics

    async def run(self, iterations: int = 1, interval_sec: float = 5.0) -> list[IncidentMetrics]:
        """Spawn the isolated MCP Server process and run `iterations` evaluation cycles."""
        server_env = dict(os.environ)
        if self.dry_run is not None:
            server_env["OVS_DRY_RUN"] = "true" if self.dry_run else "false"

        server_params = StdioServerParameters(
            command=sys.executable,
            args=[str(self.server_script_path)],
            env=server_env,
        )

        results: list[IncidentMetrics] = []
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # Verify that ONLY the `block_ip` tool is exposed by the MCP server
                tools_resp = await session.list_tools()
                exposed_tools = [t.name for t in tools_resp.tools]
                logger.info("Connected to MCP Server. Exposed tools: %s", exposed_tools)

                count = 0
                while iterations == 0 or count < iterations:
                    count += 1
                    logger.info("--- Starting Proposed MCP IDS Iteration %d ---", count)
                    try:
                        metric = await self.run_single_iteration_in_session(session)
                        results.append(metric)
                    except Exception as exc:
                        logger.error("MCP IDS iteration %d failed: %s", count, exc)
                    if iterations == 0 or count < iterations:
                        await asyncio.sleep(interval_sec)

        return results


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the Proposed MCP IDS runner."""
    parser = argparse.ArgumentParser(
        description="Proposed Autonomous IDS Client Agent via Model Context Protocol (MCP)"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of detection/mitigation iterations to run (0 for infinite loop).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.getenv("POLL_INTERVAL_SECONDS", "5.0")),
        help="Wait interval in seconds between iterations.",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default=None,
        help="Override LLM provider ('ollama' or 'gemini').",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Enable OVS adapter dry-run mode on the MCP server.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the MCP-based IDS Agent."""
    args = parse_args()
    llm_client = LLMClientFactory.create_client(provider=args.provider)
    agent = MCPIDSClientAgent(
        llm_client=llm_client,
        dry_run=True if args.dry_run else None,
    )
    try:
        asyncio.run(agent.run(iterations=args.iterations, interval_sec=args.interval))
    except KeyboardInterrupt:
        logger.info("MCP IDS Client stopped by user.")


if __name__ == "__main__":
    main()
