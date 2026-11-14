"""live_probe — which discovered hosts actually serve HTTP/HTTPS.

Reads hosts (by default from the shared ``/workspace/subdomains.txt`` that
``subdomain_enum`` wrote), probes each over HTTPS then HTTP concurrently,
buckets them by status class, and writes the responders to
``/workspace/live_hosts.txt`` — the fan-out input that every host-level tool
downstream (tech fingerprint, screenshots, nuclei, …) consumes.

This is the **fan-out point** of the recon chain. It is **Tier 1
(active-benign)**: one or two plain GET requests per host, no payloads.

Ported from recon-guru's LiveProbe, adapted to read/write the workspace and
return a small envelope instead of the full list.
"""

from __future__ import annotations

import asyncio

import httpx

from .. import scope, workspace
from ..app import mcp
from ..config import settings
from ..validate import InvalidTarget, validate_target

SOURCE_DEFAULT = "subdomains.txt"
LIVE_FILE = "live_hosts.txt"
DETAILS_FILE = "live_probe.json"
PROBE_TIMEOUT = 10  # seconds per request


def _bucket(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "other"


async def _probe(client: httpx.AsyncClient, sem: asyncio.Semaphore, host: str):
    """Return (host, scheme, status, bucket). bucket == 'dead' if no response."""
    async with sem:
        if settings.rate_limit_ms:
            await asyncio.sleep(settings.rate_limit_ms / 1000.0)
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{host}", timeout=PROBE_TIMEOUT)
                return host, scheme, r.status_code, _bucket(r.status_code)
            except Exception:
                continue  # try http, then give up
        return host, None, None, "dead"


@mcp.tool()
async def live_probe(target: str = "", source_file: str = SOURCE_DEFAULT) -> dict:
    """Probe hosts for HTTP/HTTPS liveness and record the responders.

    Tries HTTPS then HTTP for each host (redirects are *not* followed, so a
    redirect shows as 3xx). Responders are written to the shared
    ``live_hosts.txt`` for downstream tools; per-host detail goes to
    ``live_probe.json``.

    Args:
        target: Optional single host or comma-separated hosts to probe
            (e.g. "example.com" or "a.example.com,b.example.com"). When empty,
            the host list is read from the workspace file instead.
        source_file: Workspace file to read hosts from when `target` is empty.
            Defaults to "subdomains.txt" (what subdomain_enum writes).

    Returns:
        An envelope: how many were probed, how many are live, per-status-class
        bucket counts, newly added live hosts, a sample, and the output file
        paths. The full live list is in the workspace, not returned inline.
    """
    # Build the host list: explicit target(s) win, else read the workspace file.
    if target.strip():
        raw_hosts = [h.strip() for h in target.split(",") if h.strip()]
    else:
        raw_hosts = workspace.read_lines(source_file)
        if not raw_hosts:
            return {
                "ok": False,
                "error": (
                    f"no hosts to probe: workspace file '{source_file}' is empty. "
                    "Run subdomain_enum first, or pass target=..."
                ),
            }

    # Validate + scope-filter.
    valid: list[str] = []
    invalid: list[str] = []
    for h in raw_hosts:
        try:
            valid.append(validate_target(h))
        except InvalidTarget:
            invalid.append(h)
    hosts = scope.filter_in_scope(sorted(set(valid)))
    if not hosts:
        return {
            "ok": False,
            "error": "no valid, in-scope hosts to probe",
            "invalid": invalid[:20],
        }

    sem = asyncio.Semaphore(settings.max_concurrency)
    async with httpx.AsyncClient(
        verify=False,              # a cert error shouldn't mark a live host dead
        follow_redirects=False,    # so a redirect is reported as 3xx, not followed
        headers={"User-Agent": settings.user_agent},
    ) as client:
        results = await asyncio.gather(*(_probe(client, sem, h) for h in hosts))

    buckets: dict[str, list[str]] = {}
    details: dict[str, dict] = {}
    for host, sch, status, bucket in results:
        buckets.setdefault(bucket, []).append(host)
        details[host] = {"scheme": sch, "status": status, "bucket": bucket}

    responders = sorted(h for h, _, _, b in results if b != "dead")
    out_path, _, added = workspace.merge_lines(LIVE_FILE, responders)
    details_path = workspace.write_json(DETAILS_FILE, details)

    note_bits = []
    if invalid:
        note_bits.append(f"{len(invalid)} invalid host(s) skipped")
    dead = len(buckets.get("dead", []))
    if dead:
        note_bits.append(f"{dead} did not respond")

    return {
        "ok": True,
        "probed": len(hosts),
        "live": len(responders),
        "new": added,
        "buckets": {k: len(v) for k, v in sorted(buckets.items())},
        "output_file": str(out_path),
        "details_file": str(details_path),
        "sample_live": responders[:20],
        "note": "; ".join(note_bits),
    }
