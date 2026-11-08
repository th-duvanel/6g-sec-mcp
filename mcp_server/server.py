import json
import asyncio
from mcp.server.mcpserver import MCPServer
from sandbox import validate_block_rule

mcp = MCPServer("EdgeSecurityServer")

@mcp.resource("telemetry://static_logs")
def get_static_logs() -> str:
    with open("/app/data/attack_log.json", "r") as f:
        return f.read()

@mcp.tool()
def enforce_block(ip_address: str, reason: str) -> str:
    return validate_block_rule(ip_address, reason)

if __name__ == "__main__":
    asyncio.run(mcp.run_stdio_async())