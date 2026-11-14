"""dns_enum — DNS resolution and optional brute-force via dnsx.

Resolves the discovered subdomains (filtering to those that actually resolve),
records A / CNAME data, and can brute-force new subdomains from a wordlist. The
CNAME data feeds subdomain-takeover detection later. Resolved/new hosts are
merged into ``/workspace/subdomains.txt``; records go to ``/workspace/dns.json``.

**Tier 0–1** (resolution is passive; brute-force sends many DNS queries). Needs
the ``dnsx`` binary (in the Docker image); degrades gracefully if absent.
"""

from __future__ import annotations

import json

from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..sandbox import run_tool
from ..validate import InvalidTarget, validate_target

SOURCE_DEFAULT = "subdomains.txt"
SUBS_FILE = "subdomains.txt"
OUT_FILE = "dns.json"
TARGETS_TMP = "_dnsx_targets.txt"


async def _run_dnsx(argv: list[str]) -> tuple[list[dict], bool]:
    """Run dnsx -json. Returns (records, available)."""
    result = await run_tool(argv, timeout_s=settings.timeout_for("dnsx"))
    available = "not installed" not in (result.note or "")
    if not result.ok and not result.stdout.strip():
        return [], available
    records = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = d.get("host") or d.get("input") or ""
        if host:
            records.append({
                "host": host,
                "a": d.get("a", []) or [],
                "cname": d.get("cname", []) or [],
            })
    return records, available


@mcp.tool()
async def dns_enum(target: str = "", source_file: str = SOURCE_DEFAULT,
                   bruteforce: bool = False) -> dict:
    """Resolve subdomains (and optionally brute-force new ones) with dnsx.

    Args:
        target: Root domain. Required for brute-force; otherwise optional (a
            single host or comma list to resolve instead of the workspace file).
        source_file: Workspace file of hosts to resolve when `target` is empty.
            Defaults to "subdomains.txt".
        bruteforce: If True (and `target` is a domain), brute-force subdomains
            from the configured DNS wordlist.

    Returns:
        An envelope: hosts resolved, new hosts found, how many have CNAMEs, a
        sample, and the output file path. Records are written to dns.json and
        resolved/new hosts merged into subdomains.txt.
    """
    records: list[dict] = []
    available = True

    # Brute-force pass.
    if bruteforce:
        if not target.strip():
            return {"ok": False, "error": "bruteforce needs a target domain"}
        try:
            domain = validate_target(target)
        except InvalidTarget as e:
            return {"ok": False, "error": str(e)}
        brute, available = await _run_dnsx([
            "dnsx", "-d", domain, "-w", settings.dns_wordlist,
            "-a", "-cname", "-json", "-silent",
        ])
        records.extend(brute)

    # Resolve pass over the host list.
    if target.strip() and not bruteforce:
        hosts = [h.strip() for h in target.split(",") if h.strip()]
    else:
        hosts = workspace.read_lines(source_file)
    hosts = scope.filter_in_scope(sorted(set(hosts)))

    if hosts:
        targets_path = workspace.write_lines(TARGETS_TMP, hosts)
        resolved, available2 = await _run_dnsx([
            "dnsx", "-l", str(targets_path),
            "-a", "-cname", "-json", "-silent",
        ])
        available = available and available2
        records.extend(resolved)

    if not records and not available:
        return {
            "ok": False,
            "error": "dnsx binary not available — run in the Docker image",
        }

    # Deduplicate records by host, merge resolved hosts into subdomains.txt.
    by_host = {r["host"]: r for r in records}
    in_scope = scope.filter_in_scope(sorted(by_host))
    by_host = {h: by_host[h] for h in in_scope}
    workspace.write_json(OUT_FILE, by_host)
    _, total_after, added = workspace.merge_lines(SUBS_FILE, in_scope)

    with_cname = sum(1 for r in by_host.values() if r["cname"])

    return {
        "ok": True,
        "resolved": len(by_host),
        "new_subdomains": added,
        "total_subdomains": total_after,
        "with_cname": with_cname,
        "output_file": str(workspace.path(OUT_FILE)),
        "sample": in_scope[:20],
        "note": "brute-force + resolve" if bruteforce else "resolve only",
    }
