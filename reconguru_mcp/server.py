"""Server entrypoint.

Loads all tools (so they register on the FastMCP instance) and runs the server.

Transport:
  * stdio (default) — the harness launches this process and talks over a pipe.
    This is what you use locally and while developing.
  * streamable-http — set RECONGURU_TRANSPORT=http to listen on a port instead,
    for a shared/remote deployment. (Stage 6 adds auth/TLS for that mode.)
"""

from __future__ import annotations

from .app import mcp
from .config import settings
from .tools import load_tools


def main() -> None:
    loaded = load_tools()
    # Logs go to stderr so they never corrupt the stdio MCP channel on stdout.
    print(f"[reconguru-mcp] loaded tool modules: {', '.join(loaded) or '(none)'}",
          flush=True, file=__import__("sys").stderr)

    transport = settings.transport.strip().lower()
    if transport in ("http", "streamable-http"):
        mcp.run(transport="streamable-http")
    else:
        mcp.run()  # stdio


if __name__ == "__main__":
    main()
