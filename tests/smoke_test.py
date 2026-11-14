"""In-process smoke test — no harness required.

Verifies that:
  1. tools load and register on the FastMCP instance, and
  2. the nmap tool runs end-to-end (if nmap is installed) against the
     nmap project's public practice host, scanme.nmap.org.

Run:  python tests/smoke_test.py
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

# Make the package importable when run as a plain script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reconguru_mcp.app import mcp  # noqa: E402
from reconguru_mcp.tools import load_tools  # noqa: E402
from reconguru_mcp.tools.nmap import nmap_scan  # noqa: E402


async def main() -> int:
    loaded = load_tools()
    print(f"loaded tool modules: {loaded}")

    tools = await mcp.list_tools()
    names = [t.name for t in tools]
    print(f"registered tools:    {names}")
    assert "nmap_scan" in names, "nmap_scan did not register"

    # Validation guard should reject an injection-shaped target.
    bad = await nmap_scan("example.com; rm -rf /")
    assert bad.get("ok") is False, "validation should have rejected a bad target"
    print(f"rejected bad target: {bad.get('error')}")

    if shutil.which("nmap") is None:
        print("\nnmap is NOT installed on this host — skipping the live scan.")
        print("That is expected on Windows at Stage 1; the Docker image (Stage 2)")
        print("will provide nmap. The server and tool wiring are verified above.")
        return 0

    print("\nrunning a quick authorized scan of scanme.nmap.org ...")
    result = await nmap_scan("scanme.nmap.org", "-Pn -T4 --top-ports 20")
    print(f"ok={result['ok']} exit={result['exit_code']} "
          f"duration={result['duration_s']}s")
    print("---- stdout (first 800 chars) ----")
    print(result["stdout"][:800])
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
