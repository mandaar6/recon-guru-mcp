"""shodan_enrich — enrich live hosts with Shodan's internet-scan intelligence.

For each host (by default from ``/workspace/live_hosts.txt``) it resolves the
IP and queries the Shodan host API for what Shodan *already* knows: open ports,
service banners, tags, org / ISP / country, and any CVEs Shodan has flagged for
that IP. This is **passive (Tier 0)** — Shodan did the scanning; we just read
its database, sending nothing to the target.

Uses Shodan's REST API directly over ``httpx`` (no extra dependency). Requires
``RECONGURU_SHODAN_API_KEY``; without it the tool reports cleanly that it was
skipped. Writes ``/workspace/shodan.json``.

Ported from recon-guru's ShodanEnrich.
"""

from __future__ import annotations

import asyncio
import socket

import httpx

from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..validate import InvalidTarget, validate_target

SOURCE_DEFAULT = "live_hosts.txt"
OUT_FILE = "shodan.json"
HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
RATE_DELAY = 1.1  # Shodan free tier allows ~1 request/second


async def _resolve(host: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, socket.gethostbyname, host)
    except Exception:
        return None


async def _shodan_host(client: httpx.AsyncClient, ip: str, key: str) -> dict:
    try:
        r = await client.get(HOST_URL.format(ip=ip), params={"key": key}, timeout=25)
    except Exception as e:
        return {"found": False, "error": f"{type(e).__name__}"}
    if r.status_code == 404:
        return {"found": False}  # IP simply not in Shodan's data
    if r.status_code != 200:
        return {"found": False, "error": f"HTTP {r.status_code}"}
    d = r.json()
    banners = [
        {"port": item.get("port"), "banner": (item.get("data", "") or "").strip()[:300]}
        for item in d.get("data", [])
    ]
    vulns_raw = d.get("vulns")
    vulns = list(vulns_raw.keys()) if isinstance(vulns_raw, dict) else list(vulns_raw or [])
    return {
        "found": True,
        "ports": d.get("ports", []),
        "banners": banners,
        "tags": d.get("tags", []),
        "org": d.get("org", ""),
        "isp": d.get("isp", ""),
        "country": d.get("country_name", ""),
        "os": d.get("os", ""),
        "last_update": d.get("last_update", ""),
        "vulns": vulns,
    }


@mcp.tool()
async def shodan_enrich(target: str = "", source_file: str = SOURCE_DEFAULT,
                        max_hosts: int = 20, project: str = "") -> dict:
    """Enrich hosts with Shodan's passively-collected scan data.

    Args:
        target: Optional single host or comma-separated hosts. When empty, the
            host list is read from the workspace file.
        source_file: Workspace file to read hosts from when `target` is empty.
            Defaults to "live_hosts.txt".
        max_hosts: Cap on hosts queried in one call (Shodan rate-limits).
            Default 20.

    Returns:
        An envelope: hosts queried, how many Shodan had data for, how many had
        flagged vulns, a per-host summary, and the output file path. Requires a
        Shodan API key; without one it returns ok=False with needs_api_key set.
    """
    key = settings.shodan_api_key
    if not key:
        return {
            "ok": False,
            "needs_api_key": True,
            "error": "no Shodan API key configured — set RECONGURU_SHODAN_API_KEY to use this tool",
        }

    workspace.use_project(project, target)
    if target.strip():
        raw_hosts = [h.strip() for h in target.split(",") if h.strip()]
    else:
        raw_hosts = workspace.read_lines(source_file)
        if not raw_hosts:
            return {
                "ok": False,
                "error": (
                    f"no hosts: workspace file '{source_file}' is empty. "
                    "Run live_probe first, or pass target=..."
                ),
            }

    valid: list[str] = []
    for h in raw_hosts:
        try:
            valid.append(validate_target(h))
        except InvalidTarget:
            pass
    hosts = scope.filter_in_scope(sorted(set(valid)))[:max_hosts]
    if not hosts:
        return {"ok": False, "error": "no valid, in-scope hosts to enrich"}

    results: dict[str, dict] = {}
    unresolved: list[str] = []
    async with httpx.AsyncClient(headers={"User-Agent": settings.user_agent}) as client:
        for i, host in enumerate(hosts):
            ip = await _resolve(host)
            if not ip:
                unresolved.append(host)
                continue
            info = await _shodan_host(client, ip, key)
            info["ip"] = ip
            results[host] = info
            if i < len(hosts) - 1:
                await asyncio.sleep(RATE_DELAY)

    out_path = workspace.write_json(OUT_FILE, results)

    enriched = sum(1 for v in results.values() if v.get("found"))
    with_vulns = sum(1 for v in results.values() if v.get("vulns"))
    total_vulns = sum(len(v.get("vulns", [])) for v in results.values())
    summary = {
        host: {
            "ports": v.get("ports", []),
            "vulns": v.get("vulns", []),
            "org": v.get("org", ""),
        }
        for host, v in list(results.items())[:20]
        if v.get("found")
    }

    note_bits = []
    if unresolved:
        note_bits.append(f"{len(unresolved)} host(s) did not resolve")
    no_data = len(results) - enriched
    if no_data:
        note_bits.append(f"{no_data} host(s) had no Shodan data")

    return {
        "ok": True,
        "queried": len(hosts),
        "enriched": enriched,
        "hosts_with_vulns": with_vulns,
        "total_known_vulns": total_vulns,
        "output_file": str(out_path),
        "summary": summary,
        "unresolved": unresolved[:20],
        "note": "; ".join(note_bits),
    }
