"""The shared FastMCP instance.

Every tool module imports `mcp` from here and registers itself with the
`@mcp.tool()` decorator. This instance *is* the tool registry: FastMCP
auto-generates each tool's JSON schema from its type hints and docstring,
and advertises the whole set to any connected harness (Claude Code, Codex,
Cursor, etc.).

To add a tool: create a file in `reconguru_mcp/tools/`, import this `mcp`,
and decorate a function with `@mcp.tool()`. The loader in `tools/__init__.py`
imports every module in that package at startup, so the tool self-registers
with no central wiring to edit.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

# The server name is what harnesses display for this toolset.
mcp = FastMCP("reconguru-mcp")
