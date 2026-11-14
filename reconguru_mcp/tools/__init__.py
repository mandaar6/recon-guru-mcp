"""Tool package + auto-loader.

`load_tools()` imports every module in this package (except dunder/private
ones). Importing a module runs its `@mcp.tool()` decorators, which registers
its tools on the shared FastMCP instance. So "add a tool" = "add a file here" —
there is no central list to edit.
"""

from __future__ import annotations

import importlib
import pkgutil


def load_tools() -> list[str]:
    """Import all tool modules so they self-register. Returns module names loaded."""
    loaded: list[str] = []
    for mod in pkgutil.iter_modules(__path__):
        if mod.name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{mod.name}")
        loaded.append(mod.name)
    return loaded
