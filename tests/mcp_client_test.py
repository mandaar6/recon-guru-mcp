"""Real MCP client test over stdio — exactly how a harness connects.

This spawns the Dockerized server with `docker run -i --rm reconguru-mcp:latest`,
performs the MCP handshake, lists the tools, and calls nmap_scan. If this passes,
any MCP harness (Claude Code, Codex, Cursor) will work the same way.

Run:  python tests/mcp_client_test.py
"""

from __future__ import annotations

import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = StdioServerParameters(
    command="docker",
    args=["run", "-i", "--rm", "reconguru-mcp:latest"],
)


async def main() -> int:
    print("connecting to reconguru-mcp over stdio (docker)...")
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            info = await session.initialize()
            print(f"handshake OK — server: {info.serverInfo.name} "
                  f"v{info.serverInfo.version}")

            tools = await session.list_tools()
            print(f"tools advertised: {[t.name for t in tools.tools]}")

            print("\ncalling nmap_scan(scanme.nmap.org) ...")
            res = await session.call_tool(
                "nmap_scan",
                {"target": "scanme.nmap.org", "extra_args": "-Pn -T4 --top-ports 20"},
            )
            # The tool returns structured content; print the text blocks.
            for block in res.content:
                text = getattr(block, "text", None)
                if text:
                    print(text[:1200])
    print("\nMCP client test PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
