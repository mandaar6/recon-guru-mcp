"""nmap tool — the worked example of the `target + extra_args` pattern.

This is the template every other tool follows:
  1. a typed, validated `target` (scope-critical, never free-form),
  2. a free-form `extra_args` string (the agent's creative freedom — any nmap
     flags it wants), split safely into an argument list,
  3. a sensible default command when `extra_args` is empty,
  4. a structured result from the sandbox runner.

Because `extra_args` is parsed with shlex and passed as a list (never a shell
string), the agent can choose any flags without opening a shell-injection hole.
A weaker model that doesn't know nmap still gets a working scan from the default.
"""

from __future__ import annotations

import shlex

from ..app import mcp
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

# Default when the agent supplies no flags: a quick service/version scan of the
# most common 100 ports.
DEFAULT_ARGS = ["-sV", "-T4", "--top-ports", "100"]


@mcp.tool()
async def nmap_scan(target: str, extra_args: str = "") -> dict:
    """Run an nmap scan against an authorized target.

    Only scan hosts you are authorized to test. For practice, the nmap project
    provides scanme.nmap.org.

    Args:
        target: Hostname, IP address, or CIDR range to scan
            (e.g. "scanme.nmap.org", "192.0.2.10", "10.0.0.0/24").
        extra_args: Optional nmap flags as a single string, e.g.
            "-Pn -p 1-1000" (skip host discovery — useful when a host blocks
            ICMP), "-sS -T4 --top-ports 1000", or "-sV --script http-title".
            When empty, a default scan ("-sV -T4 --top-ports 100") is used.

    Returns:
        A structured result: the exact command run, exit code, stdout, stderr,
        duration, and whether it timed out or was truncated. If 0 hosts come
        back up, a hint to retry with "-Pn" is added.
    """
    try:
        tgt = validate_target(target)
    except InvalidTarget as e:
        return {"ok": False, "error": str(e)}

    if extra_args.strip():
        try:
            args = shlex.split(extra_args)
        except ValueError as e:
            return {"ok": False, "error": f"could not parse extra_args: {e}"}
    else:
        args = list(DEFAULT_ARGS)

    argv = ["nmap"] + args + [tgt]
    result = await run_tool(argv)
    out = result.to_dict()

    # A small "rich observation": nudge the agent toward the ICMP fix. This is a
    # preview of Stage 4 (structured, self-explaining outputs).
    combined = (result.stdout + result.stderr).lower()
    if "0 hosts up" in combined or "host seems down" in combined:
        out["hint"] = (
            "0 hosts responded. The target may block ICMP ping probes. "
            "Retry with extra_args including '-Pn' to skip host discovery."
        )
    return out
